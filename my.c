/*
 * ============================================================================
 * REMOTE CONSOLE - УДАЛЕННАЯ КОНСОЛЬ ДЛЯ WINDOWS
 * ============================================================================
 * 
 * ОПИСАНИЕ ПРОГРАММЫ:
 * ---------------
 * Это приложение реализует удаленный доступ к командной строке Windows (cmd.exe)
 * через сетевое соединение. По принципу работы похоже на SSH, но работает только
 * на Windows и использует TCP/IP сокеты для передачи данных.
 * 
 * АРХИТЕКТУРА:
 * -----------
 * 
 * client (my.exe -c) <--sockets--> server (my.exe -s)
 *                                        <-- pipes -->
 *                                    child process (cmd.exe)
 * 
 * КАК ЭТО РАБОТАЕТ:
 * ---------------
 * 
 * 1. СЕРВЕР (my.exe -s):
 *    - Прослушивает указанный порт (по умолчанию 8888)
 *    - При подключении клиента:
 *      a) Создает три именованных канала (pipes) для stdin, stdout и stderr
 *      b) Запускает дочерний процесс cmd.exe с перенаправленными потоками
 *      c) Создает три потока для передачи данных:
 *         * Поток 1: Сокет -> stdin cmd.exe (команды от клиента)
 *         * Поток 2: stdout cmd.exe -> Сокет (вывод командной строки)
 *         * Поток 3: stderr cmd.exe -> Сокет (ошибки)
 *    - Когда клиент отключается, все ресурсы освобождаются
 * 
 * 2. КЛИЕНТ (my.exe -c):
 *    - Подключается к серверу по указанному адресу и порту
 *    - Создает два потока:
 *      * Поток 1: stdin пользователя -> Сокет (отправка команд)
 *      * Поток 2: Сокет -> stdout пользователя (получение ответов)
 *    - Пользователь видит интерактивную консоль удаленного сервера
 * 
 * 3. WINDOWS СЛУЖБА:
 *    - Сервер может работать как Windows Service (фоновый процесс)
 *    - Установка: my.exe -install
 *    - Запуск: my.exe -start
 *    - Остановка: my.exe -stop
 *    - Удаление: my.exe -uninstall
 *    - Служба автоматически запускает сервер при старте системы
 * 
 * ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:
 * --------------------
 * 
 * Сборка:
 *   gcc -o my.exe my.c -lws2_32 -ladvapi32
 * 
 * Запуск сервера:
 *   my.exe -s 8888
 * 
 * Подключение клиента:
 *   my.exe -c 127.0.0.1 8888
 * 
 * Установка службы:
 *   my.exe -install
 *   my.exe -start
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ СОВМЕСТИМОСТИ
// ============================================================================

// Безопасная версия snprintf для совместимости
static int safe_snprintf(char* buffer, size_t size, const char* format, ...) {
    va_list args;
    int result;
    va_start(args, format);
    
#ifdef _MSC_VER
    result = _vsnprintf(buffer, size, format, args);
    if (result < 0 || (size_t)result >= size) {
        buffer[size - 1] = '\0';
        if (result < 0) result = (int)size - 1;
    }
#else
    result = vsnprintf(buffer, size, format, args);
    if (result < 0 || (size_t)result >= size) {
        buffer[size - 1] = '\0';
    }
#endif
    va_end(args);
    return result;
}

// Преобразование строки IP-адреса в структуру (замена inet_pton для совместимости)
static int string_to_addr(const char* ip_str, struct in_addr* addr) {
    unsigned long ip = inet_addr(ip_str);
    if (ip == INADDR_NONE) {
        return 0;
    }
    addr->s_addr = ip;
    return 1;
}

// ============================================================================
// 1. ПЕРЕНАПРАВЛЕНИЕ ПОТОКОВ ДЛЯ ДОЧЕРНЕГО ПРОЦЕССА
// ============================================================================
// Эта функция создает дочерний процесс (cmd.exe) и перенаправляет его
// стандартные потоки ввода/вывода/ошибок через именованные каналы (pipes).
// Это позволяет родительскому процессу получать вывод дочернего процесса
// и отправлять ему команды.

BOOL CreateChildProcessWithPipes(HANDLE hChildStd_IN_Rd, HANDLE hChildStd_OUT_Wr, 
                                  HANDLE hChildStd_ERR_Wr) {
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hChildStd_ERR_Wr;
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    siStartInfo.hStdInput = hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcess(
        NULL,
        "cmd.exe",
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &siStartInfo,
        &piProcInfo
    );

    if (!bSuccess) {
        fprintf(stderr, "CreateProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    return TRUE;
}

// ============================================================================
// 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ РАБОТЫ С СОКЕТАМИ
// ============================================================================
// Эти функции реализуют обмен данными между сокетом (клиент) и каналами
// (дочерний процесс). Используются отдельные потоки для двунаправленной
// передачи данных без блокировки.

typedef struct {
    SOCKET clientSocket;
    HANDLE hChildStd_IN_Wr;
    HANDLE hChildStd_OUT_Rd;
    HANDLE hChildStd_ERR_Rd;
} ThreadData;

// Функция потока: Читает данные из сокета и записывает в stdin дочернего процесса
// Этот поток передает команды от клиента к cmd.exe
DWORD WINAPI SocketToPipeThread(LPVOID lpParam) {
    ThreadData *data = (ThreadData*)lpParam;
    char buffer[4096];
    DWORD dwWritten;
    int bytesReceived;

    while (1) {
        bytesReceived = recv(data->clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            break;
        }

        buffer[bytesReceived] = '\0';
        WriteFile(data->hChildStd_IN_Wr, buffer, bytesReceived, &dwWritten, NULL);
    }

    return 0;
}

// Функция потока: Читает данные из stdout дочернего процесса и отправляет в сокет
// Этот поток передает стандартный вывод cmd.exe клиенту
DWORD WINAPI PipeToSocketThread(LPVOID lpParam) {
    ThreadData *data = (ThreadData*)lpParam;
    char buffer[4096];
    DWORD dwRead;
    int bytesSent;

    while (1) {
        if (!ReadFile(data->hChildStd_OUT_Rd, buffer, sizeof(buffer) - 1, &dwRead, NULL) || dwRead == 0) {
            break;
        }

        bytesSent = send(data->clientSocket, buffer, dwRead, 0);
        if (bytesSent <= 0) {
            break;
        }
    }

    return 0;
}

// Функция потока: Читает данные из stderr дочернего процесса и отправляет в сокет
// Этот поток передает поток ошибок cmd.exe клиенту
DWORD WINAPI PipeErrToSocketThread(LPVOID lpParam) {
    ThreadData *data = (ThreadData*)lpParam;
    char buffer[4096];
    DWORD dwRead;
    int bytesSent;

    while (1) {
        if (!ReadFile(data->hChildStd_ERR_Rd, buffer, sizeof(buffer) - 1, &dwRead, NULL) || dwRead == 0) {
            break;
        }

        bytesSent = send(data->clientSocket, buffer, dwRead, 0);
        if (bytesSent <= 0) {
            break;
        }
    }

    return 0;
}

// ============================================================================
// 3. РЕЖИМ СЕРВЕРА
// ============================================================================
// Сервер прослушивает указанный порт и принимает подключения клиентов.
// Для каждого клиента создается отдельный дочерний процесс cmd.exe и
// устанавливается двунаправленная связь через сокеты и каналы.

int RunServer(int port, BOOL serviceMode) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    HANDLE hChildStd_IN_Rd = NULL;
    HANDLE hChildStd_IN_Wr = NULL;
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;
    HANDLE hChildStd_ERR_Rd = NULL;
    HANDLE hChildStd_ERR_Wr = NULL;
    SECURITY_ATTRIBUTES saAttr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    if (serviceMode) {
        u_long mode = 1;
        ioctlsocket(listenSocket, FIONBIO, &mode);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    if (!serviceMode) {
        printf("Server listening on port %d\n", port);
    }

    while (1) {
        if (serviceMode && g_ServiceStopEvent != INVALID_HANDLE_VALUE) {
            if (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_OBJECT_0) {
                break;
            }
        }

        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            if (serviceMode) {
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK) {
                    Sleep(100);
                    continue;
                }
            }
            fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
            continue;
        }

        if (serviceMode) {
            u_long mode = 0;
            ioctlsocket(clientSocket, FIONBIO, &mode);
        }

        if (!serviceMode) {
            printf("Client connected from %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        }

        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0) ||
            !CreatePipe(&hChildStd_ERR_Rd, &hChildStd_ERR_Wr, &saAttr, 0) ||
            !CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0)) {
            fprintf(stderr, "CreatePipe failed: %d\n", GetLastError());
            closesocket(clientSocket);
            continue;
        }

        if (!SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0) ||
            !SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ||
            !SetHandleInformation(hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0)) {
            fprintf(stderr, "SetHandleInformation failed: %d\n", GetLastError());
            closesocket(clientSocket);
            continue;
        }

        if (!CreateChildProcessWithPipes(hChildStd_IN_Rd, hChildStd_OUT_Wr, hChildStd_ERR_Wr)) {
            closesocket(clientSocket);
            continue;
        }

        CloseHandle(hChildStd_IN_Rd);
        CloseHandle(hChildStd_OUT_Wr);
        CloseHandle(hChildStd_ERR_Wr);

        ThreadData threadData;
        threadData.clientSocket = clientSocket;
        threadData.hChildStd_IN_Wr = hChildStd_IN_Wr;
        threadData.hChildStd_OUT_Rd = hChildStd_OUT_Rd;
        threadData.hChildStd_ERR_Rd = hChildStd_ERR_Rd;

        HANDLE hThread1 = CreateThread(NULL, 0, SocketToPipeThread, &threadData, 0, NULL);
        HANDLE hThread2 = CreateThread(NULL, 0, PipeToSocketThread, &threadData, 0, NULL);
        HANDLE hThread3 = CreateThread(NULL, 0, PipeErrToSocketThread, &threadData, 0, NULL);

        if (hThread1 && hThread2 && hThread3) {
            WaitForSingleObject(hThread1, INFINITE);
            WaitForSingleObject(hThread2, INFINITE);
            WaitForSingleObject(hThread3, INFINITE);
            CloseHandle(hThread1);
            CloseHandle(hThread2);
            CloseHandle(hThread3);
        }

        CloseHandle(hChildStd_IN_Wr);
        CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_ERR_Rd);
        closesocket(clientSocket);

        if (!serviceMode) {
            printf("Client disconnected\n");
        }
    }

    closesocket(listenSocket);
    WSACleanup();
    return 0;
}

// ============================================================================
// 4. РЕЖИМ КЛИЕНТА
// ============================================================================
// Клиент подключается к серверу и передает данные между стандартными
// потоками (stdin/stdout) и сокетом. То, что пользователь вводит в консоль,
// отправляется на сервер, а ответ от сервера выводится в консоль.

typedef struct {
    SOCKET clientSocket;
} ClientThreadData;

// Функция потока: Читает данные из stdin и отправляет в сокет
// Этот поток передает команды, введенные пользователем, на сервер
DWORD WINAPI ClientStdinToSocketThread(LPVOID lpParam) {
    ClientThreadData *data = (ClientThreadData*)lpParam;
    char buffer[4096];
    DWORD dwRead;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

    while (1) {
        if (!ReadFile(hStdin, buffer, sizeof(buffer) - 1, &dwRead, NULL) || dwRead == 0) {
            break;
        }
        if (send(data->clientSocket, buffer, dwRead, 0) <= 0) {
            break;
        }
    }
    return 0;
}

// Функция потока: Читает данные из сокета и записывает в stdout
// Этот поток выводит ответы от сервера в консоль пользователя
DWORD WINAPI ClientSocketToStdoutThread(LPVOID lpParam) {
    ClientThreadData *data = (ClientThreadData*)lpParam;
    char buffer[4096];
    int bytesReceived;
    DWORD dwWritten;
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    while (1) {
        bytesReceived = recv(data->clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            break;
        }
        WriteFile(hStdout, buffer, bytesReceived, &dwWritten, NULL);
    }
    return 0;
}

// Основная функция клиента
int RunClient(const char* serverAddr, int port) {
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in server;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (!string_to_addr(serverAddr, &server.sin_addr)) {
        fprintf(stderr, "Invalid server address\n");
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    if (connect(clientSocket, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        fprintf(stderr, "connect failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    printf("Connected to server %s:%d\n", serverAddr, port);

    ClientThreadData threadData;
    threadData.clientSocket = clientSocket;

    HANDLE hThread1 = CreateThread(NULL, 0, ClientStdinToSocketThread, &threadData, 0, NULL);
    HANDLE hThread2 = CreateThread(NULL, 0, ClientSocketToStdoutThread, &threadData, 0, NULL);

    if (hThread1 && hThread2) {
        WaitForSingleObject(hThread1, INFINITE);
        WaitForSingleObject(hThread2, INFINITE);
        CloseHandle(hThread1);
        CloseHandle(hThread2);
    }

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}

// ============================================================================
// 5. WINDOWS СЛУЖБА
// ============================================================================
// Реализация Windows Service для запуска сервера в фоновом режиме.
// Служба может быть установлена, запущена, остановлена и удалена через
// Service Control Manager (SCM).

#define SERVICE_NAME "RemoteConsoleService"
#define SERVICE_PORT 8888

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

// Установка службы в системе
int InstallService() {
    SC_HANDLE scmHandle = NULL;
    SC_HANDLE serviceHandle = NULL;
    char servicePath[MAX_PATH];
    int result = 0;

    if (GetModuleFileName(NULL, servicePath, MAX_PATH) == 0) {
        fprintf(stderr, "GetModuleFileName failed: %d\n", GetLastError());
        return 1;
    }

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scmHandle == NULL) {
        fprintf(stderr, "OpenSCManager failed: %d\n", GetLastError());
        return 1;
    }

    char servicePathWithArgs[MAX_PATH + 50];
    safe_snprintf(servicePathWithArgs, sizeof(servicePathWithArgs), "%s -s -service", servicePath);

    serviceHandle = CreateService(
        scmHandle,
        SERVICE_NAME,
        SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        servicePathWithArgs,
        NULL, NULL, NULL, NULL, NULL
    );

    if (serviceHandle == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            printf("Service already exists.\n");
            result = 0;
        } else {
            fprintf(stderr, "CreateService failed: %d\n", error);
            result = 1;
        }
    } else {
        printf("Service installed successfully.\n");
        CloseServiceHandle(serviceHandle);
    }

    CloseServiceHandle(scmHandle);
    return result;
}

// Удаление службы из системы
int UninstallService() {
    SC_HANDLE scmHandle = NULL;
    SC_HANDLE serviceHandle = NULL;
    int result = 0;

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scmHandle == NULL) {
        fprintf(stderr, "OpenSCManager failed: %d\n", GetLastError());
        return 1;
    }

    serviceHandle = OpenService(scmHandle, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (serviceHandle == NULL) {
        fprintf(stderr, "OpenService failed: %d\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return 1;
    }

    SERVICE_STATUS status;
    ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(serviceHandle)) {
        fprintf(stderr, "DeleteService failed: %d\n", GetLastError());
        result = 1;
    } else {
        printf("Service uninstalled successfully.\n");
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return result;
}

// Запуск установленной службы
int StartServiceCmd() {
    SC_HANDLE scmHandle = NULL;
    SC_HANDLE serviceHandle = NULL;
    int result = 0;

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scmHandle == NULL) {
        fprintf(stderr, "OpenSCManager failed: %d\n", GetLastError());
        return 1;
    }

    serviceHandle = OpenService(scmHandle, SERVICE_NAME, SERVICE_START);
    if (serviceHandle == NULL) {
        fprintf(stderr, "OpenService failed: %d\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return 1;
    }

    if (!StartService(serviceHandle, 0, NULL)) {
        fprintf(stderr, "StartService failed: %d\n", GetLastError());
        result = 1;
    } else {
        printf("Service started successfully.\n");
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return result;
}

// Остановка запущенной службы
int StopServiceCmd() {
    SC_HANDLE scmHandle = NULL;
    SC_HANDLE serviceHandle = NULL;
    SERVICE_STATUS status;
    int result = 0;

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scmHandle == NULL) {
        fprintf(stderr, "OpenSCManager failed: %d\n", GetLastError());
        return 1;
    }

    serviceHandle = OpenService(scmHandle, SERVICE_NAME, SERVICE_STOP);
    if (serviceHandle == NULL) {
        fprintf(stderr, "OpenService failed: %d\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return 1;
    }

    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
        fprintf(stderr, "ControlService failed: %d\n", GetLastError());
        result = 1;
    } else {
        printf("Service stopped successfully.\n");
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return result;
}

// Главная функция службы (вызывается SCM при запуске службы)
VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL) {
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Обработчик команд службы (вызывается SCM при получении команд управления)
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_ServiceStopEvent);
        break;
    default:
        break;
    }
}

// Рабочий поток службы (запускает сервер)
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    RunServer(SERVICE_PORT, TRUE);
    return 0;
}

// ============================================================================
// ГЛАВНАЯ ФУНКЦИЯ ПРОГРАММЫ
// ============================================================================

// Вывод справки по использованию программы
void PrintUsage(const char* programName) {
    printf("Usage:\n");
    printf("  %s -c <server_address> [port]    - Запуск в режиме клиента\n", programName);
    printf("  %s -s [port]                     - Запуск в режиме сервера\n", programName);
    printf("  %s -s -service                   - Запуск как Windows служба\n", programName);
    printf("  %s -install                      - Установить службу\n", programName);
    printf("  %s -uninstall                    - Удалить службу\n", programName);
    printf("  %s -start                        - Запустить службу\n", programName);
    printf("  %s -stop                         - Остановить службу\n", programName);
}

// Главная функция программы
// Обрабатывает аргументы командной строки и запускает соответствующий режим работы
int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-install") == 0) {
        return InstallService();
    }
    if (strcmp(argv[1], "-uninstall") == 0) {
        return UninstallService();
    }
    if (strcmp(argv[1], "-start") == 0) {
        return StartServiceCmd();
    }
    if (strcmp(argv[1], "-stop") == 0) {
        return StopServiceCmd();
    }

    if (argc >= 3 && strcmp(argv[1], "-s") == 0 && strcmp(argv[2], "-service") == 0) {
        SERVICE_TABLE_ENTRY ServiceTable[] = {
            { (LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
            { NULL, NULL }
        };
        if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
            fprintf(stderr, "StartServiceCtrlDispatcher failed: %d\n", GetLastError());
            return 1;
        }
        return 0;
    }

    if (strcmp(argv[1], "-s") == 0) {
        int port = (argc >= 3) ? atoi(argv[2]) : 8888;
        return RunServer(port, FALSE);
    }

    if (strcmp(argv[1], "-c") == 0) {
        if (argc < 3) {
            PrintUsage(argv[0]);
            return 1;
        }
        const char* serverAddr = argv[2];
        int port = (argc >= 4) ? atoi(argv[3]) : 8888;
        return RunClient(serverAddr, port);
    }

    PrintUsage(argv[0]);
    return 1;
}


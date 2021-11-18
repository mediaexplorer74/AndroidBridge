// LOG.C

#include <common/types.h>
#include <log.h>
#include <vsprintf.h>
#include <win7compat.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdarg.h>
#include <onecore_types.h>

int logger_attached;
int logger_pipe;
static __declspec(thread) HANDLE hLoggerPipe;
static __declspec(thread) char buffer[1024];

#define PROTOCOL_VERSION	2
#define PROTOCOL_MAGIC		'flog'
struct request
{
	uint32_t magic;
	uint32_t version;
	uint32_t pid;
	uint32_t tid;
};

#define LOG_DEBUG		0
#define LOG_INFO		1
#define LOG_WARNING		2
#define LOG_ERROR		3
struct packet
{
	uint32_t packet_size;
	uint32_t type;
	uint32_t len;
	char text[];
};


// log_init_thread()
void log_init_thread()
{
	if (!logger_attached)
		return;

	LPCWSTR pipeName = L"\\\\.\\pipe\\flog_server";
	for (;;)
	{
		hLoggerPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hLoggerPipe == INVALID_HANDLE_VALUE)
		{
			/* Non critical error code, just wait and try connecting again */
			if (GetLastError() != ERROR_PIPE_BUSY || !WaitNamedPipeW(pipeName, NMPWAIT_WAIT_FOREVER))
			{


				// Open regular file instead
				// OLD
				// hLoggerPipe = CreateFileW(/*L"C:\\Data\\Users\\Public\\Documents\\*/L"flinux.log",
				
				// NEW
				hLoggerPipe = CreateFileW(L"C:\\Users\\Public\\Documents\\flinux.log",
					GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				
				hLoggerPipe = CreateFileW(/*L"C:\\Data\\Users\\Public\\Documents\\*/L"flinux.log", 
					GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				
				DWORD err = GetLastError();
				//logger_attached = 0;
				break;
			}
			continue;
		}
		/* Send initial request */
		struct request request;
		request.magic = PROTOCOL_MAGIC;
		request.version = PROTOCOL_VERSION;
		request.pid = GetProcessId(GetCurrentProcess());
		request.tid = GetThreadId(GetCurrentThread());
		DWORD written;
		if (!WriteFile(hLoggerPipe, &request, sizeof(request), &written, NULL))
		{
			CloseHandle(hLoggerPipe);
			logger_attached = 0;
		}
		logger_pipe = 1;
		break;
	}
}

void log_init()
{
	logger_pipe = 0;
	logger_attached = 1;
	log_init_thread();
}

void log_shutdown()
{
	/* TODO */
	if (logger_attached)
	{
		CloseHandle(hLoggerPipe);
	}
}

static void log_internal(int type, char typech, const char *format, va_list ap)
{
	struct packet *packet = (struct packet*)buffer;
	packet->type = type;
	FILETIME tf;
	SYSTEMTIME ts;
	win7compat_GetSystemTimePreciseAsFileTime(&tf);
	
	uint64_t time = ((uint64_t)tf.dwHighDateTime << 32ULL) + tf.dwLowDateTime; // /* Convert FILETIME to human readable text */
	uint64_t seconds = (time / 10'000'000ULL); 	/* FILETIME is in 100-nanosecond units */
	int nano = (int)(time % 10'000'000ULL);
	int sec = (int)(seconds % 60);
	int min = (int)((seconds / 60) % 60);
	int hr = (int)((seconds / 3600) % 24);
	
	packet->len = ksprintf(packet->text, "[%02u:%02u:%02u.%07u] (%c%c) ",
		hr, min, sec, nano, typech, typech);
	packet->len += kvsprintf(packet->text + packet->len, format, ap);
	packet->packet_size = sizeof(struct packet) + packet->len;
	DWORD bytes_written;

	if (logger_pipe)
	{
		if (!WriteFile(hLoggerPipe, buffer, packet->packet_size, &bytes_written, NULL))
		{
			CloseHandle(hLoggerPipe);
			logger_attached = 0;
		}
	}
	else
	{
		packet->text[packet->len] = '\n';
		packet->len++;
		packet->text[packet->len] = 0;

		OutputDebugStringA(packet->text);

		/*if (!WriteFile(hLoggerPipe, packet->text, packet->len, &bytes_written, NULL))
		{
			DWORD err = GetLastError();
			CloseHandle(hLoggerPipe);
			logger_attached = 0;
		}*/
	}

}

void log_debug_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal(LOG_DEBUG, 'D', format, ap);
}

void log_info_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal(LOG_INFO, 'I', format, ap);
}

void log_warning_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal(LOG_WARNING, 'W', format, ap);
}

void log_error_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal(LOG_ERROR, 'E', format, ap);
}

#ifdef _DEBUG

void log_assert_internal(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_internal(LOG_DEBUG, 'D', format, ap);
	process_exit(LOG_ASSERT_EXIT, 0);
}

#endif

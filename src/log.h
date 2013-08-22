#ifndef LOG_H
#define LOG_H
void log_init(const char* prefix, int verbose);
void log_debug(const char *format, ...);
void log_perror(const char *message);
void log_error(const char *format, ...);
void log_info(const char *format, ...);
void log_warning(const char *format, ...);
#endif

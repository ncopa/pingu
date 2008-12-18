#ifndef XLIB_H
#define XLIB_H

void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *str);

#endif

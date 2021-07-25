
#ifndef __READWRITE_H__
#define __READWRITE_H__

ssize_t readn(int fd, void* vptr, size_t n);
ssize_t writen(int fd, const void* vptr, size_t n);


#endif

/*
 * Copyright 2017 Kristian Evensen <kristian.evensen@gmail.com>
 *
 * This file is part of TCP closer. TCP closer is free software: you can
 * redistribute it and/or modify it under the terms of the Lesser GNU General
 * Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * TCP closer is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * TCP closer. If not, see http://www.gnu.org/licenses/.
 */

#ifndef BACKEND_EVENT_LOOP_H
#define BACKEND_EVENT_LOOP_H

#include <sys/queue.h>
#include <sys/epoll.h>
#include <stdbool.h>

#define MAX_EPOLL_EVENTS 10

//Any resource used by the callback is stored in the implementing "class".
//Assume one separate callback function per type of event
//fd is convenient in the case where I use the same handler for two file
//descriptors, for example netlink
typedef void(*backend_epoll_cb)(void *ptr, int32_t fd, uint32_t events);
typedef void(*backend_timeout_cb)(void *ptr);
typedef backend_timeout_cb backend_itr_cb;

struct backend_epoll_handle{
    void *data;
    int32_t fd;
    backend_epoll_cb cb;
};

//timeout_clock is first timeout in wallclock (ms), intvl is frequency after
//that. Set to 0 if no repeat is needed
struct backend_timeout_handle{
    uint64_t timeout_clock;
    backend_timeout_cb cb;
    LIST_ENTRY(backend_timeout_handle) timeout_next;
    uint32_t intvl;
    void *data;
};

struct backend_event_loop{
    void *itr_data;
    backend_itr_cb itr_cb;
    LIST_HEAD(timeout, backend_timeout_handle) timeout_list;
    int32_t efd;

    bool stop;
};

//Create an backend_event_loop struct
//TODO: Currently, allocations are made from heap. Add support for using
//deciding how the struct should be allocated. This also applies to
//backend_create_epoll_handle()
struct backend_event_loop* backend_event_loop_create();

//Update file descriptor + ptr to efd in events according to op
int32_t backend_event_loop_update(struct backend_event_loop *del, uint32_t events,
        int32_t op, int32_t fd, void *ptr);

//Insert timeout into list, we need manual control of adding timeouts
void backend_insert_timeout(struct backend_event_loop *del,
                            struct backend_timeout_handle *handle);
void backend_remove_timeout(struct backend_timeout_handle *timeout);

//Add a timeout which is controlled by main loop
struct backend_timeout_handle* backend_event_loop_create_timeout(
        uint64_t timeout_clock, backend_timeout_cb timeout_cb, void *ptr,
        uint32_t intvl);

//Fill handle with ptr, fd, and cb. Used by create_epoll_handle and can be used
//by applications that use a different allocater for handle
void backend_configure_epoll_handle(struct backend_epoll_handle *handle,
		void *ptr, int fd, backend_epoll_cb cb);

//Create (allocate) a new epoll handle and return it
struct backend_epoll_handle* backend_create_epoll_handle(void *ptr, int fd,
        backend_epoll_cb cb);

//Run event loop described by efd. Let it be up to the user how efd shall be
//stored
//Function is for now never supposed to return. If it returns, something has
//failed. Thus, I dont need a return value (yet)
void backend_event_loop_run(struct backend_event_loop *del);
void backend_event_loop_stop(struct backend_event_loop *del);
#endif

# epoll behavirors study

edge trigger epoll may cause [starvation](starvation.cc). As a result, [fair receive mechinism](fair_recv.cc) is used for multiple clients.


# References

* [purpose of edge trigger](https://stackoverflow.com/questions/9162712/what-is-the-purpose-of-epolls-edge-triggered-option)
* [epoll official manual](https://man7.org/linux/man-pages/man7/epoll.7.html)
* [epoll is fundamentally broken](https://idea.popcount.org/2017-02-20-epoll-is-fundamentally-broken-12)
* [use clang-format on centos](https://www.yuque.com/r/notes/share/9d36a0ba-ee62-4bec-b4b0-e14fa9c2cbd9)

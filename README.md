derp-char
---------

*Simple character device driver*

Install
-------

Manual  

    make; sudo insmod ./crypto.ko  
    ...  
    sudo rmmod crypto  

Automaic  

    sudo ./probe.sh   

Use
---

    echo "Hello World!" > /dev/crypto  
    cat /dev/crypto  

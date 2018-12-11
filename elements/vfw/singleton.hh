#ifndef CLICK_NFV_SINGLE_HH
#define CLICK_NFV_SINGLE_HH
#include <click/element.hh>

CLICK_DECLS


/**
 *  This is the class of firewall.
 *  This class take resposibility for filtering the packets that
 *  are passed to it.
 *
 * */
class Singleton : public Element { 

public:
    static Singleton& getInstance() { static Singleton ins; return ins; }
    Singleton(){}
    ~Singleton(){} 

    const char *class_name() const		{ return "Singleton"; }
    const char *port_count() const		{ return PORTS_1_1X2; }
    
    void helloworld() { printf("Hello Singleton!\n"); };

private:

};

CLICK_ENDDECLS
#endif

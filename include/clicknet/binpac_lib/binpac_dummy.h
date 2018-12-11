#ifndef BINPAC_DUMMY
#define BINPAC_DUMMY
#define DEBUG_MSG(x...) fprintf(stderr, x)
/*Dummy to link, this function suppose to be in Bro*/
double network_time();
#endif

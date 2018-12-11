#include <click/string.hh>
#include <click/utils.hh>

CLICK_DECLS

const char* skip_whitespace(const char* s, const char* end_of_s)
{
    while(s < end_of_s && (*s == ' ' || *s == '\t'))
        ++s;
    return s;
}

CLICK_ENDDECLS

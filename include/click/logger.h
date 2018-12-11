#ifndef CLICK_LOGGER_H
#define CLICK_LOGGER_H

#define LOG(fmt, args...) fprintf(stdout, fmt "\n", ##args)

#define LOGE(fmt, args...) fprintf(stderr, "[%s]\t" fmt "\n", class_name(), ##args)

#define LOG_WARN(fmt, args...) LOG("[WARN]\t" fmt, ##args)

#define LOG_ERROR(fmt, args...) LOG("[ERROR]\t" fmt, ##args)

#define LOG_INFO(fmt, args...) LOG("[INFO]\t" fmt, ##args);

#define LOG_DEBUG(fmt, args...) // LOG("[DEBUG] "__FILE__"@%d\t"fmt, __LINE__, ##args);


// for evaluation, undefine it if do not need to do evaluation
#define VIDS_EVALUATION

#ifdef VIDS_EVALUATION
    #define LOG_EVAL(fmt, args...) LOG("[EVAL]\t" fmt, ##args)
#else
    #define LOG_EVAL(fmt, args...)
#endif


#endif

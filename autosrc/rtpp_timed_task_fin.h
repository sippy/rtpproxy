/* Auto-generated by genfincode.sh - DO NOT EDIT! */
#if !defined(_rtpp_timed_task_fin_h)
#define _rtpp_timed_task_fin_h
#if !defined(RTPP_AUTOTRAP)
#define RTPP_AUTOTRAP() abort()
#else
extern int _naborts;
#endif
#if defined(RTPP_DEBUG)
struct rtpp_timed_task;
void rtpp_timed_task_fin(struct rtpp_timed_task *);
#else
#define rtpp_timed_task_fin(arg) /* nop */
#endif
#if defined(RTPP_FINTEST)
void rtpp_timed_task_fintest(void);
#endif /* RTPP_FINTEST */
#endif /* _rtpp_timed_task_fin_h */

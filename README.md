[![Build Status@GitHub](https://github.com/sobomax/libelperiodic/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/sobomax/libelperiodic/actions/workflows/main.yml?query=branch%3Amaster++)
[![Coverage Status](https://coveralls.io/repos/github/sobomax/libelperiodic/badge.svg?branch=master)](https://coveralls.io/github/sobomax/libelperiodic?branch=master)

# libElPeriodic
Library to run frequent periodic tasks.

## Principle of Operation
The libElPeriodic is designed to simplify writing control loops that are
expected to run at constant "tick" intervals with smallest possible overhead
and little or no support from the underlying run time environment.

The library is optimized to align active periods of the control loop
to the set frequency (and optionally phase as well) by applying phase
locked loop design with a proportional phase detector and a low-pass
filter as an error amplifier.

## Basic Usage

Sample usage pattern is demonstrated below. The code block denoted by the square
brackets will be executing 125.5 times a second, untul the value returned by the
`is_runnable()` routine is non-zero. Provided of course that the "logic"
does not take more than 0.01 second to run on average and that OS scheduler
plays the ball.

    #include <assert.h>
    #include <time.h>
    #include <elperiodic.h>

    extern int is_runnable(void);

    void
    event_loop(void)
    {
        double frequency = 125.5; /* Hz */
        void *elp;

        elp = prdic_init(frequency, 0.0);
        assert(elp != NULL);

        while (is_runnable()) {
    //      [----------------------];
    //      [Insert your logic here];
    //      [----------------------];
            prdic_procrastinate(elp);
        }
        prdic_free(elp);
    }

## Dispatching Calls from Worker Threads

The library also supports simple FIFO queue of function calls that have
to be dispatched by the library asynchronously in the main thread during the
"procrastination" time intervals. This allows I/O, timer and other type of
events to enter into the processing loop in a thread-safe manner.

This can be accomplished by enabling the functionality using the
`prdic_CFT_enable()` API and then scheduling necessary calls via the
`prdic_call_from_thread()` in a worker thread(s).

    #include <assert.h>
    #include <time.h>
    #include <elperiodic.h>
    #include <pthread.h>
    #include <signal.h>

    extern int do_something(void);

    struct prd_ctx {
        /* This member is initialized in the main thread */
        void *elp;
        /* This member only accessible by the main thread */
        int is_runnable;
        /* This member is filled in by the worker thread before exit */
        int result;
    };

    static void shutdown(struct prd_ctx *ctxp) {ctxp->is_runnable = 0;}

    static void
    worker_thread(void *ap)
    {
        struct prd_ctx *ctxp = (struct prd_ctx *)ap;

        ctxp->result = do_something();
        prdic_call_from_thread(ctxp->elp, (void (*)(void *))shutdown, ctxp);
    }

    int
    event_loop(void)
    {
        struct prd_ctx ctx = {.is_runnable = 1};
        double freq = 125.5; /* Hz */
        pthread_t wthr;

        ctx.elp = prdic_init(freq, 0.0);
        assert(ctx.elp != NULL);
        assert(prdic_CFT_enable(ctx.elp, SIGUSR1) == 0);

        assert(pthread_create(&wthr, NULL, (void *(*)(void *))worker_thread, &ctx) == 0);

        while (ctx.is_runnable) {
    //      [----------------------];
    //      [Insert your logic here];
    //      [----------------------];
            prdic_procrastinate(ctx.elp);
        }
        pthread_join(wthr, NULL);
        prdic_free(ctx.elp);

        return ctx.result;
    }

## Story

It came about having to write the same code over and over again in multiple
real-time projects, ranging from game [Digger](https://github.com/sobomax/digger),
RTP relay server [RTPProxy](https://github.com/sippy/rtpproxy). It has also
been recently utilized to replace a heavy-weight (and at the time not portable
to Python 3) "Twisted" framework in the
[Python Sippy B2BUA](https://github.com/sippy/b2bua) project.

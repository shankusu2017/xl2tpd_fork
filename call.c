/*
 * Layer Two Tunnelling Protocol Daemon
 * Copyright (C) 1998 Adtran, Inc.
 * Copyright (C) 2002 Jeff McAdams
 *
 * Mark Spencer
 *
 * This software is distributed under the terms
 * of the GPL, which you should have received
 * along with this source.
 *
 * Handle a call as a separate thread
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include "l2tp.h"

#include "ipsecmast.h"

// TODO DEBUG
#include <execinfo.h>

struct buffer *new_payload (struct sockaddr_in peer)
{
    struct buffer *tmp = new_buf (MAX_RECV_SIZE);
    if (!tmp)
        return NULL;
    tmp->peer = peer;
    tmp->start += sizeof (struct payload_hdr);
    tmp->len = 0;
    return tmp;
}

inline void recycle_payload (struct buffer *buf, struct sockaddr_in peer)
{
    buf->start = buf->rstart + sizeof (struct payload_hdr);
    buf->len = 0;
    buf->peer = peer;
}

/* 在 buf 的最前面加一个 l2tp 头(从 pppd 转发到对端的 l2tpd-client) */
void add_payload_hdr(struct tunnel *t, struct call *c, struct buffer *buf)
{
    struct payload_hdr *p;
    buf->start -= sizeof (struct payload_hdr);
    buf->len += sizeof (struct payload_hdr);
    /* Account for no offset */
    buf->start += 2;
    buf->len -= 2;
    if (!c->fbit && !c->ourfbit)
    {
        /* Forget about Ns and Nr fields then */
        buf->start += 4;
        buf->len -= 4;
    }
    if (!c->lbit)
    {
        /* Forget about specifying the length */
        buf->start += 2;
        buf->len -= 2;
    }
    p = (struct payload_hdr *) buf->start;
/*	p->ver = htons(c->lbit | c->rbit | c->fbit | c->ourfbit | VER_L2TP); */
    p->ver = htons (c->lbit | c->fbit | c->ourfbit | VER_L2TP);
    if (c->lbit)
    {
        p->length = htons ((_u16) buf->len);
    }
    else
    {
        p = (struct payload_hdr *) (((char *) p) - 2);
    }
    p->tid = htons (t->tid);
    p->cid = htons (c->cid);
    if (c->fbit || c->ourfbit)
    {
        p->Ns = htons (c->data_seq_num);
        p->Nr = htons (c->data_rec_seq_num);
    }
    c->data_seq_num++;
/*	c->rbit=0; */
}

/* 从 PPPD 终端读 packet，添加l2tp头后，转发给对端的 l2tp-client */
int read_packet(struct call *c)
{
    struct buffer *buf = c->ppp_buf;
    unsigned char ch;
    unsigned char escape = 0;
    unsigned char *p;
    int res;
    int errors = 0;

    p = buf->start + buf->len;
    while (1)
    {
        if (c->rbuf_pos >= c->rbuf_max)
        {
        	dlog("read packet from ppp");
            c->rbuf_max = read(c->fd, c->rbuf, sizeof (c->rbuf));
            res = c->rbuf_max;
            c->rbuf_pos = 0;
        }
        else
        {
            res = 1;
        }

        ch = c->rbuf[c->rbuf_pos++];

	/* if there was a short read, then see what is about */
        if (res < 1)
        {
            if (res == 0)
            {
                /*
                   * Hmm..  Nothing to read.  It happens
                 */
                return 0;
            }
            else if ((errno == EIO) || (errno == EINTR) || (errno == EAGAIN))
            {

                /*
                   * Oops, we were interrupted!
                   * Or, we ran out of data too soon
                   * anyway, we discarded whatever it is we
                   * have
                 */
                return 0;
            }
            errors++;
            l2tp_log (LOG_DEBUG, "%s: Error %d (%s)\n", __FUNCTION__, errno,
                 strerror (errno));
            if (errors > 10)
            {
                l2tp_log (LOG_DEBUG,
                     "%s: Too many errors.  Declaring call dead.\n",
                     __FUNCTION__);
                c->rbuf_pos = 0;
                c->rbuf_max = 0;
                return -errno;
            }
            continue;
        }

        switch (ch)
        {
        case PPP_FLAG:
            if (escape)
            {
                l2tp_log (LOG_DEBUG, "%s: got an escaped PPP_FLAG\n",
                     __FUNCTION__);
                c->rbuf_pos = 0;
                c->rbuf_max = 0;
                return -EINVAL;
            }

            if (buf->len >= 2) {
              /* must be the end, drop the FCS */
              buf->len -= 2;
            }
            else if (buf->len == 1) {
              /* Do nothing, just return the single character*/
            }
            else {
              /* if the buffer is empty, then we have the beginning
               * of a packet, not the end
               */
              break;
            }

	    /* return what we have now */
            return buf->len;

        case PPP_ESCAPE:
            escape = PPP_TRANS;
            break;

        default:
            ch ^= escape;
            escape = 0;
            if (buf->len < buf->maxlen)
            {
                *p = ch;
                p++;
                buf->len++;
                break;
            }
            l2tp_log (LOG_WARNING, "%s: read overrun\n", __FUNCTION__);
            c->rbuf_pos = 0;
            c->rbuf_max = 0;
            return -EINVAL;
        }
    }

    /* I should never get here */
    l2tp_log (LOG_WARNING, "%s: You should not see this message.  If you do, please enter "
			"a bug report at http://lists.xelerance.com/mailman/listinfo/xl2tpd", __FUNCTION__);
    return -EINVAL;
}

void call_close (struct call *c)
{
	debug_call(c);
    struct buffer *buf;
    struct schedule_entry *se, *ose;
    struct call *tmp, *tmp2;
    if (!c || !c->container)
    {
        l2tp_log (LOG_DEBUG, "%s: called on null call or containerless call\n",
             __FUNCTION__);
        return;
    }
    if (c == c->container->self)
    {
        /*
         * We're actually closing the
         * entire tunnel
         */

        /* First de-schedule any remaining packet transmissions
           for this tunnel.  That means Hello's and any remaining
           packets scheduled for transmission.  This is a very
           nasty little piece of code here. */

        se = events;
        ose = NULL;
        while (se)
        {
            if ((((struct buffer *) se->data)->tunnel == c->container)
                || ((struct tunnel *) se->data == c->container))
            {
#ifdef DEBUG_CLOSE
                l2tp_log (LOG_DEBUG, "%s: Descheduling event\n", __FUNCTION__);
#endif
                if (ose)
                {
                    ose->next = se->next;
                    if ((struct tunnel *) se->data != c->container)
                        toss ((struct buffer *) (se->data));
                    free (se);
                    se = ose->next;
                }
                else
                {
                    events = se->next;
                    if ((struct tunnel *) se->data != c->container)
                        toss ((struct buffer *) (se->data));
                    free (se);
                    se = events;
                }
            }
            else
            {
                ose = se;
                se = se->next;
            }
        }

        if (c->closing)
        {
            /* Really close this tunnel, as our
               StopCCN has been ACK'd */
#ifdef DEBUG_CLOSE
            l2tp_log (LOG_DEBUG, "%s: Actually closing tunnel %d\n", __FUNCTION__,
                 c->container->ourtid);
#endif
            destroy_tunnel (c->container);
            return;
        }

        /*
           * We need to close, but need to provide reliable delivery
           * of the final StopCCN. We record our state to know when
           * we have actually received an ACK on our StopCCN
         */
        c->closeSs = c->container->control_seq_num;
        buf = new_outgoing (c->container);
        add_message_type_avp (buf, StopCCN);
        if (c->container->hbit)
        {
            mk_challenge (c->container->chal_them.vector, VECTOR_SIZE);
            add_randvect_avp (buf, c->container->chal_them.vector,
                              VECTOR_SIZE);
        }
        add_tunnelid_avp (buf, c->container->ourtid);
        if (c->result < 0)
            c->result = RESULT_CLEAR;
        if (c->error < 0)
            c->error = 0;
        add_result_code_avp (buf, c->result, c->error, c->errormsg,
                             strlen (c->errormsg));
        add_control_hdr (c->container, c, buf);
        if (gconfig.packet_dump)
            do_packet_dump (buf);
#ifdef DEBUG_CLOSE
        l2tp_log (LOG_DEBUG, "%s: enqueing close message for tunnel\n",
             __FUNCTION__);
#endif
        control_xmit (buf);
        /*
           * We also need to stop all traffic on any calls contained
           * within us.
         */
        tmp = c->container->call_head;
        while (tmp)	// 随着 tunnal->tmp 的关闭，意味着要关闭tunnel 下所有的 call
        {
            tmp2 = tmp->next;
            tmp->needclose = 0;
            tmp->closing = -1;
			debug_call(tmp);
            call_close (tmp);
            tmp = tmp2;
        }
        l2tp_log (LOG_INFO,
             "Connection %d closed to %s, port %d (%s)\n",
             c->container->tid,
             IPADDY (c->container->peer.sin_addr),
             ntohs (c->container->peer.sin_port), c->errormsg);
    }
    else
    {
        /*
           * Just close a call
         */
        if (c->zlb_xmit)
            deschedule (c->zlb_xmit);
/*		if (c->dethrottle) deschedule(c->dethrottle); */
        if (c->closing)
        {
#ifdef DEBUG_CLOSE
            l2tp_log (LOG_DEBUG, "%s: Actually closing call %d\n", __FUNCTION__,
                 c->ourcid);
#endif
            destroy_call (c);
            return;
        }
        c->closeSs = c->container->control_seq_num;
        buf = new_outgoing (c->container);
        add_message_type_avp (buf, CDN);
        if (c->container->hbit)
        {
            mk_challenge (c->container->chal_them.vector, VECTOR_SIZE);
            add_randvect_avp (buf, c->container->chal_them.vector,
                              VECTOR_SIZE);
        }
        if (c->result < 0)
            c->result = RESULT_CLEAR;
        if (c->error < 0)
            c->error = 0;
        add_result_code_avp (buf, c->result, c->error, c->errormsg,
                             strlen (c->errormsg));
#ifdef TEST_HIDDEN
        add_callid_avp (buf, c->ourcid, c->container);
#else
        add_callid_avp (buf, c->ourcid);
#endif
        add_control_hdr (c->container, c, buf);
        if (gconfig.packet_dump)
            do_packet_dump (buf);
#ifdef DEBUG_CLOSE
        l2tp_log (LOG_DEBUG, "%s: enqueuing close message for call %d\n",
             __FUNCTION__, c->ourcid);
#endif
        control_xmit (buf);
        l2tp_log (LOG_INFO, "%s: Call %d to %s disconnected\n", __FUNCTION__,
             c->ourcid, IPADDY (c->container->peer.sin_addr));
    }
    /*
     * Note that we're in the process of closing now
     */
    c->closing = -1;
	debug_call(tmp);
}

/*
 * 提交未提交的 zlb,
 * 释放 ip
 * 发送关闭信号给 pppd 进程或强制关闭对应进程
 * 从 tunnel, lac 队列中移除
 */
void destroy_call(struct call *c)
{
    /*
     * Here, we unconditionally destroy a call.
     */

    struct call *p;
    struct timeval tv;
    pid_t pid;
    /*
     * Close the tty
     */
    if (c->fd > 0)
    {
        close (c->fd);
        c->fd = -1;
    }
/*	if (c->dethrottle) deschedule(c->dethrottle); */
    if (c->zlb_xmit)
        deschedule (c->zlb_xmit);
    toss(c->ppp_buf);

#ifdef IP_ALLOCATION
    if (c->addr) {
        unreserve_addr (c->addr);
		log_debug("0x2ea9edfb unreserve_addr: %x\n", c->addr);
    }
	/* 下面代码有隐藏的 bug，具体检索 0x32e2d745 */
    if (c->lns && c->lns->localrange) {
        unreserve_addr (c->lns->localaddr);
		log_debug("0x7df61ad0 unreserve_addr: %x, lns:%x\n", c->lns->localaddr, c->lns);
    }
#endif

    /*
     * Kill off PPPD and wait for it to
     * return to us.  This should only be called
     * in rare cases if PPPD hasn't already died
     * voluntarily（自愿）
     */
    pid = c->pppd;
    if (pid > 0)
    {
      /* Set c->pppd to zero to prevent recursion with child_handler */
      c->pppd = 0;
      /*
       * There is a bug in some PPPD versions where sending a SIGTERM
       * does not actually seem to kill PPPD, and xl2tpd waits indefinately
       * using waitpid, not accepting any new connections either. Therefor
       * we now use some more force and send it a SIGKILL instead of SIGTERM.
       * One confirmed buggy version of pppd is ppp-2.4.2-6.4.RHEL4
       * See http://bugs.xelerance.com/view.php?id=739
       *
       * Sometimes pppd takes 7 sec to go down! We don't have that much time,
       * since all other calls are suspended while doing this.
       */

#ifdef TRUST_PPPD_TO_DIE
 #ifdef DEBUG_PPPD
      l2tp_log (LOG_DEBUG, "Terminating pppd: sending TERM signal to pid %d\n", pid);
 #endif
      kill (pid, SIGTERM);	/* 通知 pppd 进制关闭，不关心 pppd 进程是否真关闭了 */
#else
 #ifdef DEBUG_PPPD
      l2tp_log (LOG_DEBUG, "Terminating pppd: sending KILL signal to pid %d\n", pid);
 #endif
      kill (pid, SIGKILL);	/* 强制关闭进程 */
#endif
    }
    if (c->container)
    {
        p = c->container->call_head;
        /*
         * Remove us from the call list, although
         * we might not actually be there
         */
        if (p)
        {
            if (p == c)
            {
                c->container->call_head = c->next;
                c->container->count--;
            }
            else
            {
                while (p->next && (p->next != c))
                    p = p->next;
                if (p->next)
                {
                    p->next = c->next;
                    c->container->count--;
                }
            }
        }
    }
    if (c->lac)
    {
        c->lac->c = NULL;
        if (c->lac->redial && (c->lac->rtimeout > 0) && !c->lac->rsched &&
            c->lac->active)
        {
#ifdef DEBUG_MAGIC
            l2tp_log (LOG_DEBUG, "Will redial in %d seconds\n",
                 c->lac->rtimeout);
#endif
            tv.tv_sec = c->lac->rtimeout;
            tv.tv_usec = 0;
            c->lac->rsched = schedule (tv, magic_lac_dial, c->lac);
        }
    }
    if(c->oldptyconf)
        free(c->oldptyconf);

    free (c);
}

/*
 * 只有三种情况下会 new_call
 *  1. new tunnel 时，顺便new 一个 call 且会进行 tunnel-self = new call, KEY: f26c6d4d
 *  2. 收到 ICRQ 消息时，新建一个 call 出来，且会放到 tunnel->call_list 的 队列头, KEY: ff317002 
 *  3. LAC_CALL 函数调用中，KEY: 1e48c24c
 */
struct call *new_call(struct tunnel *parent)
{
    unsigned char entropy_buf[2] = "\0";
    struct call *tmp = calloc (1,sizeof (struct call));

    if (!tmp)
        return NULL;
    tmp->tx_pkts = 0;
    tmp->rx_pkts = 0;
    tmp->tx_bytes = 0;
    tmp->rx_bytes = 0;
    tmp->zlb_xmit = NULL;
/*	tmp->throttle = 0; */
/*	tmp->dethrottle=NULL; */
    tmp->prx = 0;
/*	tmp->rbit = 0; */
    tmp->msgtype = 0;
/*	tmp->timeout = 0; */
    tmp->data_seq_num = 0;
    tmp->data_rec_seq_num = 0;
    tmp->pLr = -1;
    tmp->nego = 0;
    tmp->debug = 0;
    tmp->seq_reqd = 0;
    tmp->state = 0; /* Nothing so far */

    /* 若是在 new_tunnel 中 new_call, 则 parent->self 为 NULL
     * 那时候的 call 相当于一个临时的 call ,所以没有正式的 ourcid
     * 当 parent->self 已经有值的情况下， new_call 相当于要 构建一个正式的 call
     * 这时候就需要 ourcid 了
	 */
    if (parent->self)
    {
#ifndef TESTING
/*	while(get_call(parent->ourtid, (tmp->ourcid = (rand() && 0xFFFF)),0,0)); */
            /* FIXME: What about possibility of multiple random #'s??? */
            /* tmp->ourcid = (rand () & 0xFFFF); */
            get_entropy(entropy_buf, 2);
        {
            unsigned short *temp;
            temp = (unsigned short *)entropy_buf;
            tmp->ourcid = *temp & 0xFFFF;
#ifdef DEBUG_ENTROPY
            l2tp_log(LOG_DEBUG, "ourcid = %u, entropy_buf = %hx\n", tmp->ourcid, *temp);
#endif
        }
#else
        tmp->ourcid = 0x6227;
#endif
    }
    tmp->dialed[0] = 0;
    tmp->dialing[0] = 0;
    tmp->subaddy[0] = 0;
    tmp->physchan = -1;
    tmp->serno = 0;
    tmp->bearer = -1;
    tmp->cid = -1;
    tmp->qcid = -1;
    tmp->container = parent; // 指向所属的 tunnel
    /*	tmp->rws = -1; */
    tmp->fd = -1;
    tmp->rbuf_pos = 0;
    tmp->rbuf_max = 0;

    /* 若是在 new_tunel 中 new_call 则 parent->peer 是 NULL */
    tmp->ppp_buf = new_payload(parent->peer);

    tmp->oldptyconf = malloc(sizeof(struct termios));
    tmp->pnu = 0;
    tmp->cnu = 0;
    tmp->needclose = 0;
	debug_call(tmp);
    tmp->closing = 0;
    tmp->die = 0;
    tmp->pppd = 0;
    tmp->error = -1;
    tmp->result = -1;
    tmp->errormsg[0] = 0;
    tmp->fbit = 0;
    tmp->cid = 0;
    tmp->lbit = 0;
    /* Inherit LAC and LNS from parent */
    tmp->lns = parent->lns;
    tmp->lac = parent->lac;
    tmp->addr = 0;
/*	tmp->ourrws = DEFAULT_RWS_SIZE;	 */
/*	if (tmp->ourrws >= 0)
		tmp->ourfbit = FBIT;
	else */
    tmp->ourfbit = 0;           /* initialize to 0 since we don't actually use this
                                   value at this point anywhere in the code (I don't
                                   think)  We might just be able to remove it completely */
    tmp->dial_no[0] = '\0';     /* jz: dialing number for outgoing call */
    return tmp;
}

struct call *get_tunnel (int tunnel, unsigned int addr, int port)
{
    UNUSED(addr);
    UNUSED(port);
    struct tunnel *st;
    if (tunnel)
    {
        st = tunnels.head;
        while (st)
        {
            if (st->ourtid == tunnel)
            {
                return st->self;
            }
            st = st->next;
        }
    }
    return NULL;
}

/* lac->lns 
 * 查找指定tunnel下的指定call（某些情况下：新建 tunnel(内部创建一个call) 放入 tunnels队列 
 */
struct call *get_call(int tunnel, int call, struct in_addr addr, int port,
                      IPsecSAref_t refme, IPsecSAref_t refhim)
{
    /*
     * Figure out which call struct should handle this.
     * If we have tunnel and call ID's then they are unique.
     * Otherwise, if the tunnel is 0, look for an existing connection
     * or create a new tunnel.
     */
    struct tunnel *st;
    struct call *sc;
    if (tunnel)
    {
        st = tunnels.head;
        while (st)
        {
	    if (st->ourtid == tunnel &&
		(gconfig.ipsecsaref==0 ||
		 (st->refhim == refhim
		  || refhim==IPSEC_SAREF_NULL
		  || st->refhim==IPSEC_SAREF_NULL)))
            {
                if (call)
                {
                    sc = st->call_head;
                    while (sc)
                    {
			/* confirm that this is in fact a call with the right SA! */
			if (sc->ourcid == call) return sc;
                        sc = sc->next;
                    }
                    l2tp_log (LOG_DEBUG, "%s: can't find call %d in tunnel %d\n (ref=%d/%d)",
			      __FUNCTION__, call, tunnel, refme, refhim);
                    return NULL;
                }
                else
                {	/* call-id 为 0 时，没有指代特定的 call，
                     * 返回 st->self 这个专用的call 70271f3f
                     */
                    return st->self;
                }
            }
            st = st->next;
        }

        l2tp_log (LOG_INFO, "Can not find tunnel %u (refhim=%u)\n",
		  tunnel, refhim);
        return NULL;
    }
    else
    {
        /* You can't specify a call number if you haven't specified
           a tunnel silly!（愚蠢） */

        if (call)
        {
            l2tp_log (LOG_WARNING,
                 "%s: call ID specified, but no tunnel ID specified.  tossing.\n",
                 __FUNCTION__);
            return NULL;
        }
        /*
         * Well, nothing appropriate...  Let's add a new tunnel, if
         * we are not at capacity.
         */
        if (gconfig.debug_tunnel)
        {
            l2tp_log (LOG_DEBUG,
                 "%s: allocating new tunnel for host %s, port %d.\n",
                 __FUNCTION__, IPADDY (addr), ntohs (port));
        }
        if (!(st = new_tunnel ()))
        {
            l2tp_log (LOG_WARNING,
                 "%s: unable to allocate new tunnel for host %s, port %d.\n",
                 __FUNCTION__, IPADDY (addr), ntohs (port));
            return NULL;
        };

        /* 设置与之通信的 对端 socket 参数 */
        st->peer.sin_family = AF_INET;
        st->peer.sin_port = port;
		st->refme  = refme;
		st->refhim = refhim;
        st->udp_fd = -1;
        st->pppox_fd = -1;
        bcopy(&addr, &st->peer.sin_addr, sizeof(addr));

        /* 放入 tunnels 队列中 */
        st->next = tunnels.head;
        tunnels.head = st;
        tunnels.count++;
        return st->self;
    }
}

void debug_call(struct call *tc)
{
#ifndef DEBUG_CALL
	return;
#endif

	if (NULL == tc) {
		return;
	}
	if (tc->needclose == 0 && tc->closing == 0) {
		dlog("needclose and close is 0\n");
		return;
	}
	int size = 32;
	int i;
	void *array[32];
	int stack_num = backtrace(array, size);
	char **stacktrace = NULL;

	dlog("\n%s:%s needclose:%d, closing:%d \n", __FILE__, __FUNCTION__, tc->needclose, tc->closing);
	stacktrace = (char**)backtrace_symbols(array, stack_num);
 
	for (i = 0; i < stack_num; i++)
	{
		dlog("%s\n", stacktrace[i]);
	}
	free(stacktrace);
	log_debug("\n%s:%s end\n", __FILE__, __FUNCTION__);
	if (tc->needclose == 1 && tc->closing == 1) {
		dlog(" close flag is 1-1\n");
	}
}

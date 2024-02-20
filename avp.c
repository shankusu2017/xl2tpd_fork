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
 * Attribute Value Pair handler routines
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include "l2tp.h"

#define AVP_MAX 39

struct avp avps[] = {
	/*
	 * 重要的 avp，标识该 control-message 的 type 
	 */
    {0, 1, &message_type_avp, "Message Type"},
    {1, 1, &result_code_avp, "Result Code"},
    {2, 1, &protocol_version_avp, "Protocol Version"},
    {3, 1, &framing_caps_avp, "Framing Capabilities"},
    {4, 1, &bearer_caps_avp, "Bearer Capabilities"},

	/* NULL 表示不处理此类 message，下同 */
    {5, 0, NULL, "Tie Breaker"},
    {6, 0, &firmware_rev_avp, "Firmware Revision"},
    {7, 0, &hostname_avp, "Host Name"},
    {8, 1, &vendor_avp, "Vendor Name"},
    {9, 1, &assigned_tunnel_avp, "Assigned Tunnel ID"},
    {10, 1, &receive_window_size_avp, "Receive Window Size"},
    {11, 1, &challenge_avp, "Challenge"},
    {12, 0, NULL, "Q.931 Cause Code"},
    {13, 1, &chalresp_avp, "Challenge Response"},
    {14, 1, &assigned_call_avp, "Assigned Call ID"},
    {15, 1, &call_serno_avp, "Call Serial Number"},
    {16, 1, NULL, "Minimum BPS"},
    {17, 1, NULL, "Maximum BPS"},
    {18, 1, &bearer_type_avp, "Bearer Type"},
    {19, 1, &frame_type_avp, "Framing Type"},
    {20, 1, &packet_delay_avp, "Packet Processing Delay"},
    {21, 1, &dialed_number_avp, "Dialed Number"},
    {22, 1, &dialing_number_avp, "Dialing Number"},
    {23, 1, &sub_address_avp, "Sub-Address"},
    {24, 1, &tx_speed_avp, "Transmit Connect Speed"},
    {25, 1, &call_physchan_avp, "Physical channel ID"},
    {26, 0, NULL, "Initial Received LCP Confreq"},
    {27, 0, NULL, "Last Sent LCP Confreq"},
    {28, 0, NULL, "Last Received LCP Confreq"},
    {29, 1, &ignore_avp, "Proxy Authen Type"},
    {30, 0, &ignore_avp, "Proxy Authen Name"},
    {31, 0, &ignore_avp, "Proxy Authen Challenge"},
    {32, 0, &ignore_avp, "Proxy Authen ID"},
    {33, 1, &ignore_avp, "Proxy Authen Response"},
    {34, 1, NULL, "Call Errors"},
    {35, 1, &ignore_avp, "ACCM"},
    {36, 1, &rand_vector_avp, "Random Vector"},
    {37, 1, NULL, "Private Group ID"},
    {38, 0, &rx_speed_avp, "Receive Connect Speed"},
    {39, 1, &seq_reqd_avp, "Sequencing Required"}
};

char *msgtypes[] = {
    NULL, /* reserved */
    "Start-Control-Connection-Request",
    "Start-Control-Connection-Reply",
    "Start-Control-Connection-Connected",
    "Stop-Control-Connection-Notification",
    NULL, /* reserved */
    "Hello",
    "Outgoing-Call-Request",
    "Outgoing-Call-Reply",
    "Outgoing-Call-Connected",
    "Incoming-Call-Request",
    "Incoming-Call-Reply",
    "Incoming-Call-Connected",
    NULL, /* reserved */
    "Call-Disconnect-Notify",
    "WAN-Error-Notify",
    "Set-Link-Info"
};

char *stopccn_result_codes[] = {
    "Reserved",
    "General request to clear control connection",
    "General error--Error Code indicates the problem",
    "Control channel already exists",
    "Requester is not authorized to establish a control channel",
    "The protocol version of the requester is not supported--Error Code indicates the highest version supported",
    "Requester is being shut down",
    "Finite State Machine error"
};

char *cdn_result_codes[] = {
    "Reserved",
    "Call disconnected due to loss of carrier",
    "Call disconnected for the reason indicated in error code",
    "Call disconnected for administrative reasons",
    "Call failed due to lack of appropriate facilities being available (temporary condition)",
    "Call failed due to lack of appropriate facilities being available (permanent condition)",
    "Invalid destination",
    "Call failed due to no carrier detected",
    "Call failed due to detection of a busy signal",
    "Call failed due to lack of a dial tone",
    "Call was no established within time allotted by LAC",
    "Call was connected but no appropriate framing was detect"
};

void wrong_length (struct call *c, char *field, int expected, int found,
                   int min)
{
    if (min)
        snprintf (c->errormsg, sizeof (c->errormsg),
                  "%s: expected at least %d, got %d", field, expected, found);
    else
        snprintf (c->errormsg, sizeof (c->errormsg),
                  "%s: expected %d, got %d", field, expected, found);

    c->error = ERROR_LENGTH;
    c->result = RESULT_ERROR;
    c->needclose = -1;
	debug_call(c);
}

struct unaligned_u16 {
	_u16	s;
} __attribute__((packed));
/* 通知编译器按照 packed 属性处理边界对齐，
 * 避免发生 int32 这种意外的对齐 bug 
 */

/*
 * t, c, data, and datalen may be assumed to be defined for all AVP's
 *
 * 校验下 msg_type 和 call 的状态一致性（A 类型的消息是否能被B 状态机处理）
 * 构建一个 call (针对：ICRQ)
 */
int message_type_avp (struct tunnel *t, struct call *c, void *data,
                      int datalen)
{
    /*
     * This will be with every control message.  It is critical that this
     * procedure check for the validity of sending this kind of a message
     * (assuming sanity check)
     */

    struct unaligned_u16 *raw = data;
    /* 跳过 avp_hdr 头,将 message_type 暂存这里 */
    c->msgtype = ntohs(raw[3].s);
    if (datalen != 8)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG, "%s: wrong size (%d != 8)\n", __FUNCTION__,
                 datalen);
        wrong_length (c, "Message Type", 8, datalen, 0);
        return -EINVAL;
    }
    if ((c->msgtype > MAX_MSG) || (!msgtypes[c->msgtype]))
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG, "%s: unknown message type %d\n", __FUNCTION__,
                 c->msgtype);
        return -EINVAL;
    }
    if (gconfig.debug_avp)
        if (DEBUG)
            l2tp_log(LOG_DEBUG, "%s: message type %d (%s)\n", __FUNCTION__,
                     c->msgtype, msgtypes[c->msgtype]);


/* 状态转换之间的逻辑性检查（状态A是否能直接转到状态B?）
 * SANITY CHECK：完整性检查
 */
#ifdef SANITY
    if (t->sanity)
    {
        /*
         * Look out our state for each message and make sure everything
         * make sense...
         *
         * tunnel 级别的 avp, 只能是 tunnel 本身的 call 来处理
         */
        if ((c != t->self) && (c->msgtype < Hello))
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: attempting to negotiate tunnel inside a call!\n",
                     __FUNCTION__);
            return -EINVAL;
        }

        switch (c->msgtype)
        {

/**************** 通道创建 ****************/
        case SCCRQ:
            /* 初始状态和 SCCRQ 可以处理 SCCRQ, 其它状态则不行（链接已经在进行中了，
             * 不能再倒退到链接开始建立这个状态 */
            if ((t->state != 0) && (t->state != SCCRQ))
            {
                /*
                 * When we handle tie breaker AVP's, then we'll check
                 * to see if we've both requested tunnels
                 */

                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate SCCRQ with state != 0\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case SCCRP:
            if (t->state != SCCRQ)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate SCCRP with state != SCCRQ!\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case SCCCN:
            if (t->state != SCCRP)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate SCCCN with state != SCCRP!\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;

/**************** 呼叫创建 ****************/	
        case ICRQ:
            if (t->state != SCCCN)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate ICRQ when state != SCCCN\n",
                         __FUNCTION__);
                return -EINVAL;
            }
			/* 参考注释 70271f3f */
            if (c != t->self)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate ICRQ on a call!\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case ICRP:
            if (t->state != SCCCN)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate ICRP on tunnel!=SCCCN\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            if (c->state != ICRQ)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate ICRP when state != ICRQ\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case ICCN:
            if (c->state != ICRP)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate ICCN when state != ICRP\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case SLI:
            if (c->state != ICCN)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate SLI when state != ICCN\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case OCRP:             /* jz: case for ORCP */
            if (t->state != SCCCN)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate OCRP on tunnel!=SCCCN\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            if (c->state != OCRQ)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate OCRP when state != OCRQ\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case OCCN:             /* jz: case for OCCN */

            if (c->state != OCRQ)
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: attempting to negotiate OCCN when state != OCRQ\n",
                         __FUNCTION__);
                return -EINVAL;
            }
            break;
        case StopCCN:
        case CDN:
        case Hello:
            break;
        default:
            l2tp_log (LOG_WARNING, "%s: i don't know how to handle %s messages\n",
                 __FUNCTION__, msgtypes[c->msgtype]);
            return -EINVAL;
        }
    }
#endif
	/* 可以考虑把下面这一段 new_call 的业务集成到 control_finish */
    if (c->msgtype == ICRQ)
    {
        struct call *tmp;
        if (gconfig.debug_avp)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG, "%s: new incoming call\n", __FUNCTION__);
        }
        tmp = new_call(t);	/* KEY: ff317002 */
        if (!tmp)
        {
            l2tp_log (LOG_WARNING, "%s: unable to create new call\n", __FUNCTION__);
            return -EINVAL;
        }
		/* 放到队列头，后续对此有依赖 0x452f1213 */
        tmp->next = t->call_head;
        t->call_head = tmp;
        t->count++;
        /*
           * Is this still safe to assume that the head will always
           * be the most recent call being negotiated?
           * Probably...  FIXME anyway...
         */

    }
    return 0;
}

/* 随机值（用于加密方向？） */
int rand_vector_avp(struct tunnel *t, struct call *c, void *data,
                    int datalen)
{
    int size;
    struct unaligned_u16 *raw = data;
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
#ifdef SANITY
    if (t->sanity)
    {
        if (size < 0)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG, "%s: Random vector too small (%d < 0)\n",
                     __FUNCTION__, size);
            wrong_length (c, "Random Vector", 6, datalen, 1);
            return -EINVAL;
        }
        if (size > MAX_VECTOR_SIZE)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG, "%s: Random vector too large (%d > %d)\n",
                     __FUNCTION__, datalen, MAX_VECTOR_SIZE);
            wrong_length (c, "Random Vector", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    if (gconfig.debug_avp)
        l2tp_log (LOG_DEBUG, "%s: Random Vector of %d octets\n", __FUNCTION__,
             size);
    t->chal_us.vector = (unsigned char *) &raw[3].s;	/* 这里不进行 mem 拷贝 吗？*/
    t->chal_us.vector_len = size;
    return 0;
}

/* 忽略掉某些 avp */
int ignore_avp(struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * The spec says we have to accept authentication information
     * even if we just ignore it, so that's exactly what
     * we're going to do at this point.  Proxy authentication is such
     * a ridiculous security threat anyway except from local
     * controlled machines.
     *
     * FIXME: I need to handle proxy authentication as an option.
     * One option is to simply change the options we pass to pppd.
     *
     */
    UNUSED(data);
    UNUSED(datalen);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG, "%s : Ignoring AVP\n", __FUNCTION__);
    }
    return 0;
}



/* The Sequencing Required AVP, Attribute Type 39, indicates to the
 * LNS that Sequence Numbers MUST always be present on the data
 * channel
 */
int seq_reqd_avp(struct tunnel *t, struct call *c, void *data, int datalen)
{
    UNUSED(data);
#ifdef SANITY
    if (t->sanity)
    {
        if (datalen != 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Sequencing Required", 6, datalen, 1);
            return -EINVAL;
        }
        switch (c->msgtype)
        {
        case ICCN:	/* 其它的 msgtype 不能携带此消息 */
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: sequencing required not appropriate for %s!\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return -EINVAL;
        }
    }
#endif
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG, "%s: peer requires sequencing.\n", __FUNCTION__);
    }
    c->seq_reqd = -1;	/* 在 C 语言中用 1表示比 -1 更好理解 */
    return 0;
}

/* 处理对面发过来的处理结果码（针对 CDN, StopCCN 这两种消息） */
int result_code_avp(struct tunnel *t, struct call *c, void *data,
                    int datalen)
{
    /*
     * Find out what version of L2TP the other side is using.
     * I'm not sure what we're supposed to do with this but whatever..
     */

    int error = -1; /* error code unset */
    int result;
    struct unaligned_u16 *raw = data;
#ifdef SANITY
    if (t->sanity)
    {
        if (datalen < 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d < 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Result Code", 8, datalen, 1);
            return -EINVAL;
        }
        switch (c->msgtype)
        {
        /* 断开 tunnel 或者 session 时才会告知 error-reason，其它情况下发送此消息
         * 属于逻辑错误 */
        case CDN:
        case StopCCN:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: result code not appropriate for %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
    }
#endif
    result = ntohs (raw[3].s);

   /*
    * from prepare_StopCCN and prepare_CDN, note missing htons() call
    * http://www.opensource.apple.com/source/ppp/ppp-412.3/Drivers/L2TP/L2TP-plugin/l2tp.c 
    */
    if (((result & 0xFF) == 0) && (result >> 8 != 0))
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: result code endianness fix for buggy Apple client. network=%d, le=%d\n",
                 __FUNCTION__, result, result >> 8);
        result >>= 8;
    }

    if ((c->msgtype == StopCCN) && ((result > 7) || (result < 1)))
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: result code out of range (%d %d %d).  Ignoring.\n",
                 __FUNCTION__, result, error, datalen);
        return 0;
    }

    if ((c->msgtype == CDN) && ((result > 11) || (result < 1)))
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: result code out of range (%d %d %d).  Ignoring.\n",
                 __FUNCTION__, result, error, datalen);
        return 0;
    }

	/* 如果携带了错误码则读取错误码 */
    if (datalen >= 10) {
        error = ntohs (raw[4].s);
        if (((error & 0xFF) == 0) && (error >> 8 != 0))
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: error code endianness fix for buggy Apple client. network=%d, le=%d\n",
                     __FUNCTION__, error, error >> 8);
            error >>= 8;
        }
    }

    c->error = error;
    c->result = result;
    if (datalen > 10)
        safe_copy (c->errormsg, (char *) &raw[5].s, datalen - 10);
    else
        c->errormsg[0] = 0;
    if (gconfig.debug_avp)
    {
        if (DEBUG && (c->msgtype == StopCCN))
        {
            l2tp_log (LOG_DEBUG,
                 "%s: peer closing for reason %d (%s), error = %d (%s)\n",
                 __FUNCTION__, result, stopccn_result_codes[result], error,
                 c->errormsg);
        }
        else
        {
            l2tp_log (LOG_DEBUG,
                 "%s: peer closing for reason %d (%s), error = %d (%s)\n",
                 __FUNCTION__, result, cdn_result_codes[result], error,
                 c->errormsg);
        }
    }
    return 0;
}


/* 通告自己的软件版本 */
int protocol_version_avp(struct tunnel *t, struct call *c, void *data,
                         int datalen)
{
    /*
     * Find out what version of L2TP the other side is using.
     * I'm not sure what we're supposed to do with this but whatever..
     */

    int ver;
    struct unaligned_u16 *raw = data;
#ifdef SANITY
    if (t->sanity)
    {
        if (datalen != 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Protocol Version", 8, datalen, 1);
            return -EINVAL;
        }
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: protocol version not appropriate for %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
    }
#endif
    ver = ntohs (raw[3].s);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer is using version %d, revision %d.\n", __FUNCTION__,
                 (ver >> 8), ver & 0xFF);
    }
    return 0;
}

/* 对端的 frame 的同步（异步兼容能力） */
int framing_caps_avp (struct tunnel *t, struct call *c, void *data,
                      int datalen)
{
    /*
     * Retrieve the framing capabilities
     * from the peer
     */

    int caps;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: framing capabilities not appropriate for %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Framming Capabilities", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    caps = ntohs (raw[4].s);
    if (gconfig.debug_avp)
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: supported peer frames:%s%s\n", __FUNCTION__,
                 caps & ASYNC_FRAMING ? " async" : "",
                 caps & SYNC_FRAMING ? " sync" : "");
    t->fc = caps & (ASYNC_FRAMING | SYNC_FRAMING);
    return 0;
}

/* 对端支持模拟设备、数字设备？*/
int bearer_caps_avp(struct tunnel *t, struct call *c, void *data,
                    int datalen)
{
    /*
     * What kind of bearer channels does our peer support?
     */
    int caps;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: bearer capabilities not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Bearer Capabilities", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    caps = ntohs (raw[4].s);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
        {
            l2tp_log (LOG_DEBUG,
                 "%s: supported peer bearers:%s%s\n",
                 __FUNCTION__,
                 caps & ANALOG_BEARER ? " analog" : "",
                 caps & DIGITAL_BEARER ? " digital" : "");
        }

    }
    t->bc = caps & (ANALOG_BEARER | DIGITAL_BEARER);
    return 0;
}


/* FIXME: I need to handle tie breakers eventually */

/* 固件版本 */
int firmware_rev_avp(struct tunnel *t, struct call *c, void *data,
                     int datalen)
{
    /*
     * Report and record remote firmware version
     */
    int ver;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: firmware revision not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Firmware Revision", 8, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    ver = ntohs (raw[3].s);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer reports firmware version %d (0x%.4x)\n",
                 __FUNCTION__, ver, ver);
    }
    t->firmware = ver;
    return 0;
}

/* bearer type 暂不清楚用途（对端的设备类型） */
int bearer_type_avp(struct tunnel *t, struct call *c, void *data,
                    int datalen)
{
    /*
     * What kind of bearer channel is the call on?
     */
    int b;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICRQ:
        case OCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: bearer type not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Bearer Type", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    b = ntohs (raw[4].s);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer bears:%s\n", __FUNCTION__,
                 b & ANALOG_BEARER ? " analog" : "digital");
    }
    t->call_head->bearer = b;
    return 0;
}

/* 携载的 PPP 帧的类型（同步、异步）*/
int frame_type_avp(struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * What kind of frame channel is the call on?
     */
    int b;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICCN:
        case OCRQ:
        case OCCN:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: frame type not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is incorrect size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Frame Type", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    b = ntohs (raw[4].s);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer uses:%s frames\n", __FUNCTION__,
                 b & ASYNC_FRAMING ? " async" : "sync");
    }
    c->frame = b;
    return 0;
}

int hostname_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * What is the peer's name?
     */
    int size;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: hostname not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Hostname", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    if (size > MAXSTRLEN - 1)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG, "%s: truncating reported hostname (size is %d)\n",
                 __FUNCTION__, size);
        size = MAXSTRLEN - 1;
    }
    safe_copy (t->hostname, (char *) &raw[3].s, size);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer reports hostname '%s'\n", __FUNCTION__,
                 t->hostname);
    }
    return 0;
}

/* PPP 进程 环境变量 CALLED_ID 的值 */
int dialing_number_avp(struct tunnel *t, struct call *c, void *data,
                       int datalen)
{
    /*
     * What is the peer's name?
     */
    int size;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: dialing number not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Dialing Number", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    if (size > MAXSTRLEN - 1)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: truncating reported dialing number (size is %d)\n",
                 __FUNCTION__, size);
        size = MAXSTRLEN - 1;
    }
    safe_copy (t->call_head->dialing, (char *) &raw[3].s, size);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer reports dialing number '%s'\n", __FUNCTION__,
                 t->call_head->dialing);
    }
    return 0;
}

int dialed_number_avp (struct tunnel *t, struct call *c, void *data,
                       int datalen)
{
    /*
     * What is the peer's name?
     */
    int size;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case OCRQ:
        case ICRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: dialed number not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Dialed Number", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    if (size > MAXSTRLEN - 1)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: truncating reported dialed number (size is %d)\n",
                 __FUNCTION__, size);
        size = MAXSTRLEN - 1;
    }
    safe_copy (t->call_head->dialed, (char *) &raw[3].s, size);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer reports dialed number '%s'\n", __FUNCTION__,
                 t->call_head->dialed);
    }
    return 0;
}

/* 未使用到 */
int sub_address_avp(struct tunnel *t, struct call *c, void *data,
                    int datalen)
{
    /*
     * What is the peer's name?
     */
    int size;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case OCRP:
        case ICRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: sub_address not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Sub-address", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    if (size > MAXSTRLEN - 1)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: truncating reported sub address (size is %d)\n",
                 __FUNCTION__, size);
        size = MAXSTRLEN - 1;
    }
    safe_copy (t->call_head->subaddy, (char *) &raw[3].s, size);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer reports subaddress '%s'\n", __FUNCTION__,
                 t->call_head->subaddy);
    }
    return 0;
}

int vendor_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * What vendor makes the other end?
     */
    int size;
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: vendor not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Vendor", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    if (size > MAXSTRLEN - 1)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG, "%s: truncating reported vendor (size is %d)\n",
                 __FUNCTION__, size);
        size = MAXSTRLEN - 1;
    }
    safe_copy (t->vendor, (char *) &raw[3].s, size);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer reports vendor '%s'\n", __FUNCTION__, t->vendor);
    }
    return 0;
}

int challenge_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * We are sent a challenge
     */
    struct unaligned_u16 *raw = data;
    int size;
#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: challenge not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "challenge", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    /* size = raw[0].s & 0x0FFF; */
    /* length field of AVP's is only 10 bits long, not 12 */
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    /* if (size != MD_SIG_SIZE)
    {
        l2tp_log (LOG_DEBUG, "%s: Challenge is not the right length (%d != %d)\n",
             __FUNCTION__, size, MD_SIG_SIZE);
        return -EINVAL;
    } */
    if (t->chal_us.challenge)
	free(t->chal_us.challenge);
    t->chal_us.challenge = malloc(size);
    if (t->chal_us.challenge == NULL)
    {
        return -ENOMEM;
    }
    bcopy (&raw[3].s, (t->chal_us.challenge), size);
    t->chal_us.chal_len = size;
    t->chal_us.state = STATE_CHALLENGED;
    if (gconfig.debug_avp)
    {
        l2tp_log (LOG_DEBUG, "%s: challenge avp found\n", __FUNCTION__);
    }
    return 0;
}

int chalresp_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * We are sent a challenge
     */
    struct unaligned_u16 *raw = data;
    int size;
#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCCN:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: challenge response not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen < 6)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is too small.  %d < 6\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "challenge", 6, datalen, 1);
            return -EINVAL;
        }
    }
#endif
    size = raw[0].s & 0x03FF;
    size -= sizeof (struct avp_hdr);
    if (size != MD_SIG_SIZE)
    {
        l2tp_log (LOG_DEBUG, "%s: Challenge is not the right length (%d != %d)\n",
             __FUNCTION__, size, MD_SIG_SIZE);
        return -EINVAL;
    }

    bcopy (&raw[3].s, t->chal_them.reply, MD_SIG_SIZE);
    if (gconfig.debug_avp)
    {
        l2tp_log (LOG_DEBUG, "%s: Challenge reply found\n", __FUNCTION__);
    }
    return 0;
}


/* tunnel id ： KEY_MEMBER
 * ID 是对端向我通告本次通信中：它的 ID 是多少，在后续通信中，
 * 发往对端的消息里需要携带此ID，方便对端找到对应的 tunnel 的数据，
 * 下面的call id 同理
 */
int assigned_tunnel_avp(struct tunnel *t, struct call *c, void *data,
                        int datalen)
{
    /*
     * What is their TID that we must use from now on?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
        case StopCCN:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: tunnel ID not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Assigned Tunnel ID", 8, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    if (c->msgtype == StopCCN)
    {
        t->qtid = ntohs (raw[3].s);	/* 0x3174badb */
    	log_debug("0x1ba25d34 qtid: %d\n", t->qtid);
    }
    else
    {
        t->tid = ntohs (raw[3].s);
    }
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: using peer's tunnel %d\n", __FUNCTION__,
                 ntohs (raw[3].s));
    }
    return 0;
}

/* call id */
int assigned_call_avp (struct tunnel *t, struct call *c, void *data,
                       int datalen)
{
    /*
     * What is their CID that we must use from now on?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case CDN:
        case ICRP:
        case ICRQ:
        case OCRP:             /* jz: deleting the debug message */
            break;
        case OCRQ:
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: call ID not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Assigned Call ID", 8, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    if (c->msgtype == CDN)
    {
    /* 
     * 表示发起方本端需要关闭的 call-id，  qtid 也一样 0x3174badb
     *
     * A----CDN----> B
     * t.id = 3      t.id = 300
     * c.id = 2      c.id = 200
     *
     * CDN 消息中 qcid 不是对端B的 200 而是消息发送方的 2
     * 
     */
        c->qcid = ntohs (raw[3].s);	/* 先记录值，后续再校验该值 */
		log_debug("0x1ba25d34 qcid: %d\n", c->qcid);
    }
    else if (c->msgtype == ICRQ)
    {	/* 
         * NOTE: 代码默认这边新构建了一个 call 且放到了队列头，
         * 若不是这样，则需要修改代码, 找到对应的 call 0x452f1213
         *
         * 这里记录下对方的 call id
    	 */
        t->call_head->cid = ntohs(raw[3].s);
    }
    else if (c->msgtype == ICRP)
    {
        c->cid = ntohs (raw[3].s);
    }
    else if (c->msgtype == OCRP)
    {                           /* jz: copy callid to c->cid */
        c->cid = ntohs (raw[3].s);
    }
    else
    {
        l2tp_log (LOG_DEBUG, "%s:  Dunno what to do when it's state %s!\n",
             __FUNCTION__, msgtypes[c->msgtype]);
    }
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: using peer's call %d\n", __FUNCTION__, ntohs (raw[3].s));
    }
    return 0;
}

/* 未启用 packet processing delay */
int packet_delay_avp (struct tunnel *t, struct call *c, void *data,
                      int datalen)
{
    /*
     * What is their CID that we must use from now on?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICRP:
        case OCRQ:
        case ICCN:
        case OCRP:
        case OCCN:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: packet delay not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Assigned Call ID", 8, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    c->ppd = ntohs (raw[3].s);
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer's delay is %d 1/10's of a second\n", __FUNCTION__,
                 ntohs (raw[3].s));
    }
    return 0;
}

int call_serno_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * What is the serial number of the call?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICRQ:
        case OCRQ:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: call ID not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
#ifdef STRICT
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Serial Number", 10, datalen, 0);
            return -EINVAL;
#else
            l2tp_log (LOG_DEBUG,
                 "%s: peer is using old style serial number.  Will be invalid.\n",
                 __FUNCTION__);
#endif

        }
    }
#endif
    t->call_head->serno = (((unsigned int) ntohs (raw[3].s)) << 16) |
        ((unsigned int) ntohs (raw[4].s));
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: serial number is %d\n", __FUNCTION__,
                 t->call_head->serno);
    }
    return 0;
}

int rx_speed_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * What is the received baud rate of the call?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICCN:
        case OCCN:
        case OCRP:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: rx connect speed not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Connect Speed (RX)", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    c->rxspeed = (((unsigned int) ntohs (raw[3].s)) << 16) |
        ((unsigned int) ntohs (raw[4].s));
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: receive baud rate is %d\n", __FUNCTION__, c->rxspeed);
    }
    return 0;
}

int tx_speed_avp (struct tunnel *t, struct call *c, void *data, int datalen)
{
    /*
     * What is the transmit baud rate of the call?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICCN:
        case OCCN:
        case OCRP:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: tx connect speed not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Connect Speed (tx)", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    c->txspeed = (((unsigned int) ntohs (raw[3].s)) << 16) |
        ((unsigned int) ntohs (raw[4].s));
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: transmit baud rate is %d\n", __FUNCTION__, c->txspeed);
    }
    return 0;
}

/* Physical channel ID */
int call_physchan_avp(struct tunnel *t, struct call *c, void *data,
                      int datalen)
{
    /*
     * What is the physical channel?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case ICRQ:
        case OCRQ:
        case OCRP:
        case OCCN:
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: physical channel not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 10)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 10\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Physical Channel", 10, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    t->call_head->physchan = (((unsigned int) ntohs (raw[3].s)) << 16) |
        ((unsigned int) ntohs (raw[4].s));
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: physical channel is %d\n", __FUNCTION__,
                 t->call_head->physchan);
    }
    return 0;
}

int receive_window_size_avp (struct tunnel *t, struct call *c, void *data,
                             int datalen)
{
    /*
     * What is their RWS?
     */
    struct unaligned_u16 *raw = data;

#ifdef SANITY
    if (t->sanity)
    {
        switch (c->msgtype)
        {
        case SCCRP:
        case SCCRQ:
        case OCRP:             /* jz */
        case OCCN:             /* jz */
        case StopCCN:
/*		case ICRP:
		case ICCN: */
            break;
        default:
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: RWS not appropriate for message %s.  Ignoring.\n",
                     __FUNCTION__, msgtypes[c->msgtype]);
            return 0;
        }
        if (datalen != 8)
        {
            if (DEBUG)
                l2tp_log (LOG_DEBUG,
                     "%s: avp is wrong size.  %d != 8\n", __FUNCTION__,
                     datalen);
            wrong_length (c, "Receive Window Size", 8, datalen, 0);
            return -EINVAL;
        }
    }
#endif
    t->rws = ntohs (raw[3].s);
/*	if (c->rws >= 0)
		c->fbit = FBIT; */
    if (gconfig.debug_avp)
    {
        if (DEBUG)
            l2tp_log (LOG_DEBUG,
                 "%s: peer wants RWS of %d.  Will use flow control.\n",
                 __FUNCTION__, t->rws);
    }
    return 0;
}


int handle_avps (struct buffer *buf, struct tunnel *t, struct call *c)
{
    /*
     * buf's start should point to the beginning of a packet. We assume it's
     * a valid packet and has had check_control done to it, so no error
     * checking is done at this point.
     */

    /* TODO: Refactor function to not use "goto next" */

    struct avp_hdr *avp;
    int len = buf->len - sizeof(struct control_hdr);
    int firstavp = -1; /* 初始为 1 可能更好理解*/
    int hidlen = 0;
    char *data = buf->start + sizeof (struct control_hdr);
    avp = (struct avp_hdr *) data;
    /* I had to comment out the following since Valgrind tells me it leaks like my bathroom faucet
    if (gconfig.debug_avp)
        l2tp_log (LOG_DEBUG, "%s: handling avp's for tunnel %d, call %d\n",
             __FUNCTION__, t->ourtid, c->ourcid);
    */
    while (len > 0)
    {
        hidlen = 0;
        /* Go ahead and byte-swap the header */
        swaps (avp, sizeof (struct avp_hdr));
        /* 不认识的属性ID */
        if (avp->attr > AVP_MAX)
        {
            if (AMBIT (avp->length))
            {
                l2tp_log (LOG_WARNING,
                     "%s:  don't know how to handle mandatory attribute %d.  Closing %s.\n",
                     __FUNCTION__, avp->attr,
                     (c != t->self) ? "call" : "tunnel");
                set_error (c, VENDOR_ERROR,
                           "mandatory attribute %d cannot be handled",
                           avp->attr);
                c->needclose = -1;
				debug_call(c);
                return -EINVAL;
            }
            else
            {
                if (DEBUG)
                    l2tp_log (LOG_WARNING,
                         "%s:  don't know how to handle attribute %d.\n",
                         __FUNCTION__, avp->attr);
                goto next;
            }
        }
        if (ALENGTH (avp->length) > len)
        {
            l2tp_log (LOG_WARNING,
                 "%s: AVP received with length > remaining packet length!\n",
                 __FUNCTION__);
            set_error (c, ERROR_LENGTH, "Invalid AVP length");
            c->needclose = -1;
			debug_call(c);
            return -EINVAL;
        }
		// 第一个 AVP 必须是 message_type 的 avp 
        if (avp->attr && firstavp)
        {
            l2tp_log (LOG_WARNING, "%s: First AVP was not message type.\n",
                 __FUNCTION__);
            set_error (c, VENDOR_ERROR, "First AVP must be message type");
            c->needclose = -1;
			debug_call(c);
            return -EINVAL;
        }
        if (ALENGTH (avp->length) < sizeof (struct avp_hdr))
        {
            l2tp_log (LOG_WARNING, "%s: AVP with too small of size (%d).\n",
                 __FUNCTION__, ALENGTH (avp->length));
            set_error (c, ERROR_LENGTH, "AVP too small");
            c->needclose = -1;
			debug_call(c);
            return -EINVAL;
        }
        if (AZBITS (avp->length))
        {
            l2tp_log (LOG_WARNING, "%s: %sAVP has reserved bits set.\n", __FUNCTION__,
                 AMBIT (avp->length) ? "Mandatory " : "");
            if (AMBIT (avp->length))
            {
                set_error (c, ERROR_RESERVED, "reserved bits set in AVP");
                c->needclose = -1;
				debug_call(c);
                return -EINVAL;
            }
            goto next;
        }
        if (AHBIT (avp->length))
        {
#ifdef DEBUG_HIDDEN
            l2tp_log (LOG_DEBUG, "%s: Hidden bit set on AVP.\n", __FUNCTION__);
#endif
            /* We want to rewrite the AVP as an unhidden AVP
               and then pass it along as normal.  Remember how
               long the AVP was in the first place though! */
            hidlen = avp->length;
            if (decrypt_avp (data, t))
            {
                if (gconfig.debug_avp)
                    l2tp_log (LOG_WARNING, "%s: Unable to handle hidden %sAVP\n:",
                         __FUNCTION__,
                         (AMBIT (avp->length) ? "mandatory " : ""));
                if (AMBIT (avp->length))
                {
                    set_error (c, VENDOR_ERROR, "Invalid Hidden AVP");
                    c->needclose = -1;
					debug_call(c);
                    return -EINVAL;
                }
                goto next;
            };
            len -= 2;
            hidlen -= 2;
            data += 2;
            avp = (struct avp_hdr *) data;
            /* Now we should look like a normal AVP */
        }
        else
            hidlen = 0;

        if (!avps[avp->attr].handler)
        {
            if (AMBIT (avp->length))
            {
                l2tp_log (LOG_WARNING,
                     "%s:  No handler for mandatory attribute %d (%s).  Closing %s.\n",
                     __FUNCTION__, avp->attr, avps[avp->attr].description,
                     (c != t->self) ? "call" : "tunnel");
                set_error (c, VENDOR_ERROR, "No handler for attr %d (%s)\n",
                           avp->attr, avps[avp->attr].description);
                return -EINVAL;
            }
            else
            {
                if (DEBUG)
                    l2tp_log (LOG_WARNING, "%s:  no handler for attribute %d (%s).\n",
                         __FUNCTION__, avp->attr,
                         avps[avp->attr].description);
                goto next;
            }
        }

        if (avps[avp->attr].handler (t, c, avp, ALENGTH (avp->length)))
        {
            if (AMBIT (avp->length))
            {
                l2tp_log (LOG_WARNING,
                     "%s: Bad exit status handling attribute %d (%s) on mandatory packet.\n",
                     __FUNCTION__, avp->attr,
                     avps[avp->attr].description);
                c->needclose = -1;
				debug_call(c);
                return -EINVAL;
            }
            else
            {
                if (DEBUG)
                    l2tp_log (LOG_DEBUG,
                         "%s: Bad exit status handling attribute %d (%s).\n",
                         __FUNCTION__, avp->attr,
                         avps[avp->attr].description);
            }
        }

      next:
        if (hidlen && ALENGTH(hidlen))
        {
            /* Skip over the complete length of the hidden AVP */
            len -= ALENGTH (hidlen);
            data += ALENGTH (hidlen);
        }
        else if (ALENGTH(avp->length))
        {
            len -= ALENGTH (avp->length);
            data += ALENGTH (avp->length);      /* Next AVP, please */
        }
        else
        {
            l2tp_log (LOG_WARNING, "%s: broken avp->length zero %d\n", __FUNCTION__,avp->length);
            break;
        }
        avp = (struct avp_hdr *) data;
        firstavp = 0;
    }
    if (len != 0)
    {
        l2tp_log (LOG_WARNING, "%s: negative overall packet length\n", __FUNCTION__);
        return -EINVAL;
    }
    return 0;
}

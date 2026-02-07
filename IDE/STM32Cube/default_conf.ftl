[#ftl]
/**
  ******************************************************************************
  * File Name          : ${name}
  * Description        : This file provides code for the configuration
  *                      of the ${name} instances.
  ******************************************************************************
[@common.optinclude name=mxTmpFolder+"/license.tmp"/][#--include License text --]
  ******************************************************************************
  */
[#assign s = name]
[#assign toto = s?replace(".","_")]
[#assign toto = toto?replace("/","")]
[#assign toto = toto?replace("-","_")]
[#assign inclusion_protection = toto?upper_case]
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __${inclusion_protection}__
#define __${inclusion_protection}__

#ifdef __cplusplus
 extern "C" {
#endif


/* Includes ------------------------------------------------------------------*/
[#if includes??]
[#list includes as include]
#include "${include}"
[/#list]
[/#if]

[#-- SWIPdatas is a list of SWIPconfigModel --]
[#list SWIPdatas as SWIP]
[#-- Global variables --]
[#if SWIP.variables??]
	[#list SWIP.variables as variable]
extern ${variable.value} ${variable.name};
	[/#list]
[/#if]

[#-- Global variables --]

[#assign instName = SWIP.ipName]
[#assign fileName = SWIP.fileName]
[#assign version = SWIP.version]

/**
	MiddleWare name : ${instName}
	MiddleWare fileName : ${fileName}
	MiddleWare version : ${version}
*/
[#if SWIP.defines??]
	[#list SWIP.defines as definition]
/*---------- [#if definition.comments??]${definition.comments}[/#if] -----------*/
#define ${definition.name} #t#t ${definition.value}
[#if definition.description??]${definition.description} [/#if]
	[/#list]
[/#if]



[/#list]

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFIP_STM32_CUBEMX
#define NO_FILESYSTEM

/* ------------------------------------------------------------------------- */
/* Socket Pool Configuration */
/* ------------------------------------------------------------------------- */
#if defined(WOLFIP_CONF_MAX_TCP) && WOLFIP_CONF_MAX_TCP > 0
    #define MAX_TCPSOCKETS      WOLFIP_CONF_MAX_TCP
#else
    #define MAX_TCPSOCKETS      4
#endif

#if defined(WOLFIP_CONF_MAX_UDP) && WOLFIP_CONF_MAX_UDP > 0
    #define MAX_UDPSOCKETS      WOLFIP_CONF_MAX_UDP
#else
    #define MAX_UDPSOCKETS      2
#endif

#if defined(WOLFIP_CONF_MAX_ICMP) && WOLFIP_CONF_MAX_ICMP > 0
    #define MAX_ICMPSOCKETS     WOLFIP_CONF_MAX_ICMP
#else
    #define MAX_ICMPSOCKETS     2
#endif

/* ------------------------------------------------------------------------- */
/* Buffer Configuration */
/* ------------------------------------------------------------------------- */
#if defined(WOLFIP_CONF_MTU) && WOLFIP_CONF_MTU > 0
    #define LINK_MTU            WOLFIP_CONF_MTU
#else
    #define LINK_MTU            1536
#endif

#define RXBUF_SIZE              (LINK_MTU * 16)
#define TXBUF_SIZE              (LINK_MTU * 16)

/* ------------------------------------------------------------------------- */
/* Network Configuration */
/* ------------------------------------------------------------------------- */
#define ETHERNET
#define MAX_NEIGHBORS           16

/* ------------------------------------------------------------------------- */
/* Enable/Disable Features */
/* ------------------------------------------------------------------------- */

/* DHCP Client */
#if defined(WOLFIP_CONF_DHCP) && WOLFIP_CONF_DHCP == 1
    #define WOLFIP_ENABLE_DHCP
#endif

/* DNS Client */
#if defined(WOLFIP_CONF_DNS) && WOLFIP_CONF_DNS == 1
    #define WOLFIP_ENABLE_DNS
#endif

/* Loopback Interface */
#undef WOLFIP_ENABLE_LOOPBACK
#if defined(WOLFIP_CONF_LOOPBACK) && WOLFIP_CONF_LOOPBACK == 1
    #define WOLFIP_ENABLE_LOOPBACK  1
    #ifndef WOLFIP_MAX_INTERFACES
        #define WOLFIP_MAX_INTERFACES   2
    #endif
#else
    #define WOLFIP_ENABLE_LOOPBACK  0
#endif

/* IP Forwarding */
#undef WOLFIP_ENABLE_FORWARDING
#if defined(WOLFIP_CONF_FORWARDING) && WOLFIP_CONF_FORWARDING == 1
    #define WOLFIP_ENABLE_FORWARDING    1
#else
    #define WOLFIP_ENABLE_FORWARDING    0
#endif

#ifndef WOLFIP_MAX_INTERFACES
    #define WOLFIP_MAX_INTERFACES   1
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if defined(WOLFIP_CONF_DEBUG) && WOLFIP_CONF_DEBUG == 1
    #define DEBUG
#else
    #undef DEBUG
#endif

/* ------------------------------------------------------------------------- */
/* wolfSSL Integration */
/* ------------------------------------------------------------------------- */
/* Define WOLFSSL_WOLFIP to enable wolfSSL IO callbacks for TLS support.
 * Requires wolfSSL Cube Pack to be installed and configured.
 */
/* #define WOLFSSL_WOLFIP */

#ifdef __cplusplus
}
#endif
#endif /* ${inclusion_protection}_H */

/**
  * @}
  */

/*****END OF FILE****/

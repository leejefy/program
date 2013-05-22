
/*
Copyright (c) 2011,  Shenzhen Hexicom Technologies Co., Ltd.
All rights reserved.

File         : aspfunc.c
Status       : Current
Description  :	

Author       : Einsn Liu
Contact      : liuchuansen@hexicomtech.com

Revision     : 2011-09-18
Description  : Primary beta released
*/



/*
 * aspfunc.c
 *
 *  Created on: Jan 10, 2011
 *      Author: root
 */

#include	"uemf.h"
#include	"wsIntrn.h"
#include	<signal.h>
#include	<unistd.h>
#include	<time.h>

#include	<client.h>


#define WEBS_CONFIG_FILE 		"config.bin"
#define WEBS_SYSLOG_FILE 		"syslog.txt"
#define 

extern ipc_agent_t agent;

#ifdef EOC_PIBFW_UPGRADE	
char upload_pib[128 + 8];
char upload_fw[128 + 8];
#endif /* EOC_PIBFW_UPGRADE	*/


vendor_info_t vendor_info; 

/*
Deprecated

static const char *cnu_auth_string(int auth)
{
	static const char *str[] = {"any", "any", "acc", "blk"};

	if (auth < sizeof(str)/sizeof(char *)){
		return str[auth];
	}
	return str[0];
}
*/




char *websQueryString(webs_t wp, char *varname, char *val, int size)
{
	char *cp = strstr(wp->query, varname), *ep;
	if(!cp) return NULL;
	while(*cp && *cp != '=') cp ++;
	if(*cp) {
		cp ++;
		strncpy(val, cp, size - 1);
		ep = val;
		while(*ep && *ep != '&') ep ++;
		*ep = 0;
		return val;
	}
	else
		return NULL;
}


int asp_get_variable(int eid, webs_t wp, int argc, char_t **argv)
{
	int i, value = 0;	
	struct {
		char *name;
		int value;
	}asp_variable_table[] = {
		{"EOC_MAX_VLAN_NUMS",	MAX_VLAN_NUMS},
		{"EOC_MAX_DEVS_NUMS",	MAX_SUPPORTED_MODEL_NUM},
		{"EOC_MAX_TMPL_NUMS",	MAX_TMPL_NUMS},
		{"EOC_MAX_USER_NUMS",	MAX_USER_NUMS},
		{"MAX_PIB_CONFIG_NUM",	MAX_PIB_CONFIG_NUM},
		{"MAX_PIB_APPLY_NUM",	MAX_PIB_APPLY_NUM},	
#ifdef NSCRTV_EXT	
        {"MAX_CNU_WHITELIST_NUM",  MAX_CNU_WHITELIST_NUM},
        {"MAX_CNU_SERVICE_NUM",  MAX_CNU_SERVICE_NUM},
        {"MAX_CNU_VLANPOOL_NUM",  MAX_CNU_VLANPOOL_NUM},      		
#endif  
		{.name = NULL}
	};

	for(i = 0; asp_variable_table[i].name; i++) {
		if(!strcmp(asp_variable_table[i].name, argv[0])) {
			value = asp_variable_table[i].value; 
		}
	}
	
	return websWrite(wp, T("%d"), value);
}	


static char *vlan_member_string(uint32_t member)
{
	static char buf[80];
	int if_phys[] = {CLT_PHY_LIST, ETH_PHY_LIST};
	char* if_names[] = {CLT_IFNAME_LIST, ETH_IFNAME_LIST};
	int i, len = 0;
	buf[0] = 0;
	for (i = 0; i < sizeof(if_phys)/ sizeof(if_phys[0]); i ++){
		if (member & (1 << if_phys[i])){
			len += sprintf(buf + len, "%s%s", (len != 0) ? "," : "", if_names[i]);
		}
	}
	return buf;
}


/*
char ifname[IFNAMSIZ];
uint8_t phy;
uint8_t enabled;
uint8_t autoneg;
uint8_t speed;
uint8_t duplex;
uint8_t flowctrl;
uint8_t priority;
uint32_t ingress_limit;
uint32_t egress_limit;
uint8_t ingress_filter;
uint16_t pvid;// read only

eth0;1;0;1;1000;full;1;off;0;0;0;4094

*/

static int asp_get_ethernet_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i, vlen = 0, ret;
	switch_interface_t *info, *ifp;
	char buffer[512];

	int num = MAX_CLT_ETH_PORTS;
	info = (switch_interface_t  *)malloc(sizeof(*info) * num);
	if (info == NULL){
		DBG_ASSERT(0, "malloc(%d)", sizeof(*info) * num);
		return 0;
	}
	memset(info, 0, sizeof(*info) * num);

	// TODO initialize the default values
	for (i = 0; i < num; i ++){
		sprintf(info[i].ifname, "eth%d", i);
	}

	ret = ipc_switch_interface_get(&agent, NULL, info, &num);
	ipc_assert(ret);
	
	ifp = info;
	for(i = 0; i < num; i ++, ifp ++) {
		vlen = sprintf(buffer, "%s;%d;%d;%d", ifp->ifname, ifp->phy, ifp->enabled, ifp->autoneg);
		vlen += sprintf(buffer + vlen, ";%s;%s;%d", speed_itoa(ifp->speed), ifp->duplex ? "full" : "half", ifp->flowctrl);
		if (ifp->priority == ETH_PRIORITY_OFF){
			vlen += sprintf(buffer + vlen, ";%s", "off");
		}else {
			vlen += sprintf(buffer + vlen, ";%d", ifp->priority);
		} 		
		vlen += sprintf(buffer + vlen, ";%u;%u;%d;%d", ifp->ingress_limit, ifp->egress_limit, ifp->ingress_filter, ifp->pvid);
		wlen += websWrite(wp, T("'%s'%s"),buffer, (i == num - 1) ? "" : ",\n");
	}
	if (info) free(info);
	
	return wlen;
}


static int asp_get_vlan_interface_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i, v, vlen = 0;
	ipc_packet_t *pack = NULL;
	switch_vlan_interface_t* vlanif;
	switch_vlan_group_t *vlan_group;
//	char vs[24];
	char buffer[128];
	char tagbuf[4096*4];
	char untagbuf[4096*4];

	pack = ipc_switch_vlan_interface_config(agent.ipc_fd, agent.agent, IPC_OP_GET, 0, NULL);
	if(pack && pack->header.ack_status == IPC_STATUS_OK) {
		vlanif = (switch_vlan_interface_t *)pack->payloads;
		for(i = 0; i < pack->header.payload_num; i ++) {
			/* we will print out something like that
			'eth0;access;1;;',
			'eth1;trunk;1;;',
			'cab0;trunk;1;201,202,203;',
			'cab1;hybrid;1;303,304;123,85' ; 
			// for hybrid , the last second part is always for tag vlans.
			// and the last part is for untag vlans
			*/
			vlen = sprintf(buffer, "%s;%s;%d;", vlanif->ifname,  switchport_itoa(vlanif->mode), vlanif->pvid);

			// get buffer tag
			tagbuf[0] = 0;
			untagbuf[0] = 0;

			if (vlanif->count && (vlanif->mode == ETH_SWITCHPORT_TRUNK)){
				vlan_group = vlanif->trunk_hybrid;
				vlan_group_sprintf(tagbuf, vlan_group);
			}else if (vlanif->count && (vlanif->mode == ETH_SWITCHPORT_HYBRID)){
				vlan_group = vlanif->trunk_hybrid;
				for (v = 0; v < vlanif->count; v ++){
					if (vlan_tagged(vlan_group->flag)){
						vlan_group_sprintf(tagbuf, vlan_group);
					}else {
						vlan_group_sprintf(untagbuf, vlan_group);
					}
					vlan_group = vlan_group_to_next(vlan_group);
				}
			}
			
			//buffer[vlen] = 0;
			wlen += websWrite(wp, T("'%s%s;%s'%s"),buffer, tagbuf, untagbuf, (i == pack->header.payload_num - 1) ? "" : ",\n");
			vlanif = vlan_interface_to_next(vlanif);
		}
	}
	if(pack) free(pack);
	return wlen;
}



static int asp_get_vlan_mode_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i,vlen = 0, ret;
	switch_vlan_mode_t info;
	char buffer[512];

	memset(&info, 0, sizeof(info));

	ret = ipc_switch_vlan_mode_get(&agent, &info);
	ipc_assert(ret);

	vlen = sprintf(buffer, "'%d','%d'", info.mode, info.mvlan);
	
	for(i = 0; i < sizeof(info.ports)/sizeof(info.ports[0]); i ++) {
		if (info.ports[i].ifname[0]){
			vlen += sprintf(buffer + vlen, ",'%s;%s'", 
				info.ports[i].ifname, switchport_itoa(info.ports[i].type));
		}else {
			continue;
		}
	}
	wlen = websWrite(wp, T("%s"),buffer);

	return wlen;
}



static int asp_get_vlan_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i, vlen = 0, num, ret;
	switch_vlan_group_t *info, *vlan_group = NULL;
	char buffer[4096*4];

	ret = ipc_switch_vlan_group_get(&agent, NULL, 0, &info, &num);
	ipc_assert(ret);

	if (info && num){
		vlan_group = info;
		for(i = 0; i < num; i ++) {
			vlen = sprintf(buffer, "%d;%s;", i, vlan_member_string(vlan_group->member));
			vlen += vlan_group_sprintf(buffer + vlen, vlan_group);
			wlen += websWrite(wp, T("'%s'%s"),buffer, (i == num - 1) ? "" : ",\n");
			vlan_group = vlan_group_to_next(vlan_group);
		}		
	}

	if(info) free(info);
	return wlen;
}

static int asp_get_user_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i;
	ipc_packet_t *pack = NULL;
	cnu_user_config_t *user;
	char macstr[64];

	pack = ipc_cnu_user_config(agent.ipc_fd, agent.agent, IPC_OP_GET, 0, NULL);
	if(pack && pack->header.ack_status == IPC_STATUS_OK) {
		user = (cnu_user_config_t *)pack->payloads;

		for(i = 0; i < pack->header.payload_num; i ++, user ++) {
			hexstring(macstr, sizeof(macstr), user->mac.octet, sizeof(ether_addr_t));
			wlen += websWrite(wp, T("'%s;%d;%d;%s;%s;%s;%d'%s"),
					/*user->user_id,*/
					macstr,
					user->tmpl_id,
					user->device_id,
					user->auth == CNU_AUTH_ACCEPT ? "acc" : "blk",
					user->name,
					user->desc,
					user->user_id,
					(i == pack->header.payload_num - 1) ? "" : ",\n");
		}
	}
	if(pack) free(pack);
	return wlen;
}

/*
static char *port_map_string(char *str, uint8_t *map, int ports)
{
	int i, len = 0;
	for(i = 0; i < ports; i ++) {
		len += sprintf(str + len, "%d", map[i]);
		if(i < ports - 1) len += sprintf(str + len, ",");
	}
	return str;
}
*/

static int asp_get_devinfo(int eid, webs_t wp, int argc, char_t **argv)
{
	static cnu_devinfo_t supported_devices[MAX_SUPPORTED_MODEL_NUM];
	static int supported_base_devices_num = 0;
	static int supported_devices_num = 0;
	int i, get_num, wlen = 0, ret;

	if (supported_devices_num == 0){
		supported_devices_num = sizeof(supported_devices)/sizeof(supported_devices[0]);
		ret = ipc_supported_device_get(&agent, supported_devices, &supported_devices_num);
		ipc_assert(ret);		

		if (ret == IPC_STATUS_OK){
			for (i = 0; i < supported_devices_num; i ++){
				if (supported_devices[i].dev_id & 0x80){
					break;
				}
				supported_base_devices_num ++;
			}
		}
	}
	
	if ((supported_devices_num == 0)
		|| (supported_base_devices_num == 0)){
		return 0;
	}

	if ((argc > 0) && !strcasecmp(argv[0], "all")){
		get_num = supported_devices_num;
	}else {
		get_num = supported_base_devices_num;
	}
	
	for(i = 0; i < get_num; i ++) {
		wlen += websWrite(wp, T("'%s;%d;%d;%d;%d'%s"),
				supported_devices[i].model,
				supported_devices[i].port_num,
				supported_devices[i].base_id,
				supported_devices[i].dev_id,
				supported_devices[i].tmpl_id,
				(i == get_num - 1) ? "" : ",\n");
	}		
	return wlen;
}

static int asp_get_templates(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i, ret;
	ipc_packet_t *pack = NULL;
	char query_id[32];	
	int tmpl_id = -1;

    	int for_device = 0;
    	cnu_id_t cnu_id;
    
	cnu_template_config_t *ptmpl, tmpl;
	char *port_speeds[] = {"10", "100", "1000"};


	if (argc < 1){
		DBG_ASSERT(0, "Invalid asp argument");
		return 0;		
	}else if(!strcasecmp(argv[0], "brief")) {
		char vlans[256];
		int j, len;
		pack = ipc_cnu_template_config(agent.ipc_fd, agent.agent, IPC_OP_GET, 0, NULL, NULL);
		if(pack && pack->header.ack_status == IPC_STATUS_OK) {
			ptmpl = (cnu_template_config_t *)pack->payloads;
			for(i = 0; i < pack->header.payload_num; i ++, ptmpl ++){
				len = sprintf(vlans, "%d", ptmpl->lsw_cfg.ports[0].pvid);
				for (j = 1; j < ptmpl->lsw_cfg.port_num; j ++){
					len += sprintf(vlans + len, ",%d", ptmpl->lsw_cfg.ports[j].pvid);
				}
				wlen += websWrite(wp, T("'%d;%d;%s;%s;%s'%s"),
						ptmpl->tmpl_id,
						ptmpl->device_id,
						ptmpl->tmpl_name,
						ptmpl->tmpl_desc,
						vlans,
						(i == pack->header.payload_num- 1) ? "" : ",\n");
			}
		}
		if (pack) free(pack);			
	}else {
		if (argc >= 2){
			if(websQueryString(wp, argv[1], query_id, sizeof(query_id) - 1)){
                if (strchr(query_id, ':') 
                    && (hexencode(cnu_id.mac.octet, sizeof(cnu_id.mac), query_id) == sizeof(ether_addr_t))){
                    for_device = 1;
                    cnu_id.type = CNU_ID_TYPE_MAC;
                } else {
				    tmpl_id = atoi(query_id);
                }
			}			
		}
		cnu_template_set_default(&tmpl);

        if (for_device){
            cnu_infos_t cnu_info;
        	ret = ipc_cnu_info_get_by_mac(&agent, &cnu_id.mac, &cnu_info);
        	ipc_assert(ret);

            if (ret == IPC_STATUS_OK){
                tmpl.device_id = cnu_info.device_id;
                tmpl.tmpl_id = cnu_info.template_id;
                safe_strncpy(tmpl.tmpl_name, cnu_info.username, sizeof(tmpl.tmpl_name));
            }                
            if ((ret != IPC_STATUS_OK) || !cnu_info.linkup){
                tmpl.tmpl_id = -2;
            }
    
        }else {
    		tmpl.tmpl_id = tmpl_id;
    			
    		if (valid_template_id_with_default(tmpl_id)){
    			ret = ipc_cnu_template_config_query(&agent, tmpl_id, &tmpl);
    			ipc_assert(ret);
    		}else {
                DBG_ASSERT(tmpl_id == -1, "Invalid Template Id:%d", tmpl_id);
            }
        }
		wlen += websWrite(wp, T("var tmpl_brief='%d;%d;%s;%s';\n"),
				tmpl.tmpl_id,
				tmpl.device_id,
				tmpl.tmpl_name,
				tmpl.tmpl_desc);
#ifdef FOR_CVNCHINA	        
        wlen += websWrite(wp, T("var tmpl_misc='%d;%d;%d;%d;%s';\n"),
#else 
        wlen += websWrite(wp, T("var tmpl_misc='%d;%d;%s;%d;%s';\n"),
#endif 
				tmpl.cable_rate_up,
				tmpl.cable_rate_dn,
#ifdef FOR_CVNCHINA				
				(tmpl.lsw_cfg.broadcast_storm == 1) ? ((320 << 20) | (320 << 10) | 320) : tmpl.lsw_cfg.broadcast_storm,
#else 
                tmpl.lsw_cfg.broadcast_storm ? "on" : "off",
#endif /* */
				tmpl.mac_limit,
				tmpl.lsw_cfg.vlan_transparent ? "on" : "off");
		wlen += websWrite(wp, T("var tmpl_ports=new Array(\n"));

		for(i = 0; i < tmpl.lsw_cfg.port_num; i ++) {
			wlen += websWrite(wp, T("'%d;%s;%s;%d;%s;%d;%d;%s;%d;%s'%s"),
					i,
					tmpl.lsw_cfg.ports[i].autoneg ? "auto" :
							(tmpl.lsw_cfg.ports[i].speed <= 2 ? port_speeds[tmpl.lsw_cfg.ports[i].speed] : "100"),
					tmpl.lsw_cfg.ports[i].autoneg ? "auto" :
							(tmpl.lsw_cfg.ports[i].duplex ? "full" : "half"),
					tmpl.lsw_cfg.ports[i].priority,
					tmpl.lsw_cfg.ports[i].flowctrl ? "on" : "off",
					// CABLE UP -> EGRESS DOWN -> INGRESS
					(i == 0) ? tmpl.lsw_cfg.ports[i].egress_rate_limit : tmpl.lsw_cfg.ports[i].ingress_rate_limit,
					(i == 0) ? tmpl.lsw_cfg.ports[i].ingress_rate_limit : tmpl.lsw_cfg.ports[i].egress_rate_limit,
					tmpl.lsw_cfg.ports[i].tagged ? "on" : "off",
					tmpl.lsw_cfg.ports[i].pvid,
					tmpl.lsw_cfg.ports[i].disabled ? "dis" : "ena",
					(i == tmpl.lsw_cfg.port_num - 1) ? "" : ",\n");
		}
		wlen += websWrite(wp, T(");\n"));		
	}

	return wlen;
}


static int asp_get_syslog(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char line[320];
	int wlen = 0;

	fp = fopen(SYSLOG_FILE_PATH, "r");
	if(fp) {
		while(!feof(fp)) {
			fgets(line, sizeof(line), fp);
			if(!feof(fp)) {
				wlen += websWrite(wp, T("%s"), line);
			}
		}
		fclose(fp);
	}
	else {
		DBG_PRINTF("Fail to open log file!");
	}
	return wlen;
}


static int asp_dump_sysconfig(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char line[1024];
	int wlen = 0;

	fp = popen("nvram show", "r");
	if(fp) {
		while(!feof(fp)) {
			fgets(line, sizeof(line), fp);
			if(!feof(fp)) {
				wlen += websWrite(wp, T("%s"), line);
			}
		}
		pclose(fp);
	}
	else {
		wlen += websWrite(wp, T("Failed to open file 'nvram show'!\r\n"));
	}
	return wlen;
}


static int asp_dump_debuginfo(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char line[1024];
	int wlen = 0;

	wlen += websWrite(wp, T("System Call: cat /proc/meminfo\r\n"));

	fp = popen("cat /proc/meminfo", "r");
	if(fp) {
		while(!feof(fp)) {
			fgets(line, sizeof(line), fp);
			if(!feof(fp)) {
				wlen += websWrite(wp, T("%s"), line);
			}
		}
		pclose(fp);
	}
	else {
		wlen += websWrite(wp, T("Failed to open file 'cat /proc/meminfo'!\r\n"));
	}

	wlen += websWrite(wp, T("System Call: ps\r\n"));

	fp = popen("ps", "r");
	if(fp) {
		while(!feof(fp)) {
			fgets(line, sizeof(line), fp);
			if(!feof(fp)) {
				wlen += websWrite(wp, T("%s"), line);
			}
		}
		pclose(fp);
	}
	else {
		wlen += websWrite(wp, T("Failed to open file 'ps'!\r\n"));
	}
	
	return wlen;
}


#if 0
static int webs_put_file(webs_t wp, char *path)
{
	FILE *fp;
	char buffer[WEBS_BUFSIZE];
	int wlen = 0, rlen;

	fp = fopen(path, "r");
	if(fp) {
		while(!feof(fp)) {
			rlen = fread(buffer, sizeof(unsigned char), sizeof(buffer), fp);
			if(!feof(fp) && (rlen > 0)) {
				websWriteBlock(wp, buffer, rlen);
			}
			wlen += rlen;
		}
		fclose(fp);
	}
	else {
		DBG_PRINTF("Fail to open file : %s!", path);
	}
	return wlen;
}


static int asp_get_files(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen;
	ipc_system_ack_t *pack;
	if(argc < 1) {
		DBG_ASSERT(0, "Invalid asp argument");
		return 0;
	}
	else {
		if(!strcasecmp(argv[0], WEBS_CONFIG_FILE)) {	
			pack = ipc_system_req(ipc_fd, IPC_CONFIG_GET, 0);
			if (pack && (pack->status == IPC_STATUS_OK)){
				wlen = webs_put_file(wp, SYS_CONFIG_TMP_FILE);
			}
			if (pack) free(pack);
		}else if (!strcasecmp(argv[0], WEBS_SYSLOG_FILE)){
			wlen = webs_put_file(wp, SYSLOG_FILE_PATH);
		}
	}
	return wlen;
}
#endif 

int asp_get_config_file_ready(void)
{
	int ret;
	ret = ipc_system_request(&agent, IPC_SYS_CONFIG_BACKUP, 0);
	ipc_assert(ret);
	
	return (ret == IPC_STATUS_OK) ? 1 : 0;
}

static int asp_cnu_info(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_infos_t cnu_info;
	char mac[24];
	int ret, wlen = 0;


	if ((argc < 1) || (argv[0] == NULL)){
		DBG_ASSERT(0, "Invalid arguments");
		return 0;
	}

	if(!websQueryString(wp, argv[0], mac, sizeof(mac))) {
		DBG_ASSERT(0, "Invalid query string");
		return 0;
	}

	memset(&cnu_info, 0, sizeof(cnu_info));
	
	ret = hexencode(cnu_info.mac.octet, sizeof(cnu_info.mac), mac);
	if(ret != sizeof(ether_addr_t)) {
		DBG_ASSERT(0, "Invalid MAC address");
		return 0;
	}

	ret = ipc_cnu_info_get_by_mac(&agent, &cnu_info.mac, &cnu_info);
	ipc_assert(ret);

	wlen += websWrite(wp, T("'%d;%d;%s;%d;%d;%d;%s;%d;%d;%s;%d;%d;%lu;%d;%s'"),
			cnu_info.clt,			// Mater Channel ID
			cnu_info.index,		// STA ID
			mac,	// STA Mac Address
			cnu_info.tei,	// STA TEI
			cnu_info.avgtx,	// TX Rate
			cnu_info.avgrx,	// RX Rate
			cnu_info.alias,	// HFID
			cnu_info.link,					// Link status
			cnu_info.auth,//cnu_auth_string(cnu_info.auth),		// Auth status
			cnu_info.username,						// Alias
			cnu_info.device_id,	// device id
			cnu_info.template_id,
			cnu_info.online_tm ? (time(NULL) - cnu_info.online_tm) : 0,	// Online time
			cnu_info.atten,
			cnu_info.version				
			);
		
	return wlen;
}


static int asp_cnu_mibs(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_port_mib_t  cnu_mib[CNU_MAX_PORT_NUM];
	cnu_id_t cnu_id;
	char mac[24];
	int ret, wlen = 0, port, num;


	if ((argc < 1) || (argv[0] == NULL)){
		DBG_ASSERT(0, "Invalid arguments");
		return 0;
	}

	if(!websQueryString(wp, argv[0], mac, sizeof(mac))) {
		DBG_ASSERT(0, "Invalid query string");
		return 0;
	}

	cnu_id.type = CNU_ID_TYPE_MAC;
	
	ret = hexencode(cnu_id.mac.octet, sizeof(cnu_id.mac), mac);
	if(ret != sizeof(ether_addr_t)) {
		DBG_ASSERT(0, "Invalid MAC address");
		return 0;
	}

	memset(cnu_mib, 0, sizeof(cnu_mib));
	num = sizeof(cnu_mib)/sizeof(cnu_mib[0]);
	ret = ipc_cnu_port_stats_get(&agent, 0, &cnu_id, cnu_mib, &num);
	ipc_assert(ret);

	for(port = 0; port < num; port++) {
		wlen += websWrite(wp, T("'%d;%d;%d;%lu;%lu;%lu;%lu'%s"),
				port,
				cnu_mib[port].link,
				cnu_mib[port].spd,
				cnu_mib[port].txpacket,
				cnu_mib[port].rxpacket,
				cnu_mib[port].pkt_unit, // 0 pkts,  1 bytes
				0, (port == num - 1) ? "" : ",\n"
				);
	}
	
	return wlen;
}


static int asp_cnu_config_dump(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_id_t cnu_id;
	char mac[24];
	int ret, wlen = 0, i;
    cnu_config_dump_t config;


	if ((argc < 1) || (argv[0] == NULL)){
		DBG_ASSERT(0, "Invalid arguments");
		return 0;
	}

	if(!websQueryString(wp, argv[0], mac, sizeof(mac))) {
		DBG_ASSERT(0, "Invalid query string");
		return 0;
	}

	cnu_id.type = CNU_ID_TYPE_MAC;
	
	ret = hexencode(cnu_id.mac.octet, sizeof(cnu_id.mac), mac);
	if(ret != sizeof(ether_addr_t)) {
		DBG_ASSERT(0, "Invalid MAC address");
		return 0;
	}

	memset(&config, 0, sizeof(config));
    
	ret = ipc_cnu_config_get(&agent, 0, &cnu_id, &config);
	ipc_assert(ret);

    wlen += websWrite(wp, T("var cnu_config = new Array();\n"));

    if (ret != IPC_STATUS_OK){
        wlen += websWrite(wp, T("cnu_config['mac'] = '-2';\n"));        
    }else {
        wlen += websWrite(wp, T("cnu_config['mac'] = '%02X:%02X:%02X:%02X:%02X:%02X';\n"), config.mac.octet[0],
            config.mac.octet[1],
            config.mac.octet[2],
            config.mac.octet[3],
            config.mac.octet[4],
            config.mac.octet[5]);   
        
        wlen += websWrite(wp, T("cnu_config['check'] = '%s;%s;%d';\n"), 
            (config.flag & HAS_PIB) ? "yes" : "no",
            (config.flag & HAS_LSW) ? "yes" : "no",
            config.lsw_type
        );   

        if (config.flag & HAS_PIB){
            wlen += websWrite(wp, T("cnu_config['pib'] = '%d;%d;%d;%d;%d;TODO: Host Interface Mode';\n"), 
                config.pib_up_stream_limit,
                config.pib_down_stream_limit,
                config.pib_mac_limit,
                config.pib_vlan_id,
                config.pib_igmp_snooping
                // TODO: IGMP Snooping
            );   
        }
        
        if (config.flag & HAS_LSW){
            
            wlen += websWrite(wp, T("cnu_config['swmisc'] = '%d;%d;%d;%d;%d;%d;%d';\n"),
                (config.lsw_global_control & LSW_VLAN_ENABLE) ? 1 : 0,  
                (config.lsw_global_control & LSW_VLAN_TRUNK_ENABLE) ? 1 : 0,  
                (config.lsw_global_control & LSW_VLAN_TAG_AWARE) ? 1 : 0,  
                (config.lsw_global_control & LSW_LOOP_DETECT_ENABLE) ? 1 : 0,  
                (config.lsw_global_control & LSW_BCAST_FILTER_ENABLE) ? 1 : 0,  
                (config.lsw_global_control & LSW_MCAST_FILTER_ENABLE) ? 1 : 0,  
                (config.lsw_global_control & LSW_UCAST_FILTER_ENABLE) ? 1 : 0
                );
        
            for (i = 0; i < config.lsw_port_num; i ++){
                char name[8];
                if (i == 0){
                    strcpy(name, "swcab");
                }else {
                    sprintf(name, "sweth%d", i - 1);
                }
                wlen += websWrite(wp, T("cnu_config['%s'] = '%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d';\n"), 
                    name,
                    i,
                    config.lsw_port_config[i].enable,
                    config.lsw_port_config[i].mode_auto,
                    config.lsw_port_config[i].mode_speed,
                    config.lsw_port_config[i].mode_duplex,
                    config.lsw_port_config[i].flowctrl,
                    config.lsw_port_config[i].priority,                    
                    // CABLE UP -> EGRESS DOWN -> INGRESS
                    (i == 0) ? config.lsw_port_config[i].egress_limit : config.lsw_port_config[i].ingress_limit,
                    (i == 0) ? config.lsw_port_config[i].ingress_limit : config.lsw_port_config[i].egress_limit,
                    config.lsw_port_config[i].tagging,
                    config.lsw_port_config[i].pvid,
                    config.lsw_port_config[i].phy
                );                                  
            }
 
        }        

        
    }    
    
	return wlen;
}



static int asp_cnu_bridge_dump(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_id_t cnu_id;
	char mac[24];
	int ret, wlen = 0, i;
    eoc_bridge_info_t config;


	if ((argc < 1) || (argv[0] == NULL)){
		DBG_ASSERT(0, "Invalid arguments");
		return 0;
	}

	if(!websQueryString(wp, argv[0], mac, sizeof(mac))) {
		DBG_ASSERT(0, "Invalid query string");
		return 0;
	}

	cnu_id.type = CNU_ID_TYPE_MAC;
	
	ret = hexencode(cnu_id.mac.octet, sizeof(cnu_id.mac), mac);
	if(ret != sizeof(ether_addr_t)) {
		DBG_ASSERT(0, "Invalid MAC address");
		return 0;
	}

	memset(&config, 0, sizeof(config));
    
	ret = ipc_cnu_bridge_info_get(&agent, 0, &cnu_id, &config);
	ipc_assert(ret);

    if (ret != IPC_STATUS_OK){
         wlen += websWrite(wp, T("'-2'")); 
    }else {
         wlen += websWrite(wp, T("'%d'%s"), config.mac_num, (config.mac_num == 0) ? "" : ",\n");
         for (i  = 0; i < config.mac_num; i ++){
            wlen += websWrite(wp, T("'%s'%s"), 
            mac2str(&config.macs[i]),
            (i == config.mac_num - 1) ? "" : ",\n");    
         }            
    }
	return wlen;
}


///*  Add by Jefy Lee. 2013.3.23 */
static int asp_clt_bridge_dump(int eid, webs_t wp, int argc, char_t **argv)
{
	char mac[24];
	clt_id_t clt_id;
	int ret, wlen = 0, i;
    eoc_bridge_info_t config;

	if ((argc < 1) || (argv[0] == NULL)){
		DBG_ASSERT(0, "Invalid arguments");
		return 0;
	}

	if(!websQueryString(wp, argv[0], mac, sizeof(mac))) {
		DBG_ASSERT(0, "Invalid query string");
		return 0;
	}

	clt_id.index = 1;
	
	ret = hexencode(clt_id.mac.octet, sizeof(clt_id.mac), mac);
	if(ret != sizeof(ether_addr_t)) {
		DBG_ASSERT(0, "Invalid MAC address");
		return 0;
	}

	memset(&config, 0, sizeof(config));

	ret = ipc_clt_bridge_info_get(&agent, 0, &clt_id, &config);
	ipc_assert(ret);

    if (ret != IPC_STATUS_OK){
         wlen += websWrite(wp, T("'-2'")); 
    }else {
         wlen += websWrite(wp, T("'%d'%s"), config.mac_num, (config.mac_num == 0) ? "" : ",\n");
         for (i  = 0; i < config.mac_num; i ++){
            wlen += websWrite(wp, T("'%s'%s"), 
            mac2str(&config.macs[i]),
            (i == config.mac_num - 1) ? "" : ",\n");    
         }            
    }
	return wlen;

}

static int asp_cnu_link_stats(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_id_t cnu_id;
	cable_link_stats_t link_stats;
	char mac[24], stat_str[128];
	int ret, wlen = 0;
		


	if ((argc < 1) || (argv[0] == NULL)){
		DBG_ASSERT(0, "Invalid arguments");
		return 0;
	}

	if(!websQueryString(wp, argv[0], mac, sizeof(mac))) {
		DBG_ASSERT(0, "Invalid query string");
		return 0;
	}
	
	cnu_id.type = CNU_ID_TYPE_MAC;
	
	ret = hexencode(cnu_id.mac.octet, sizeof(cnu_id.mac), mac);
	if(ret != sizeof(ether_addr_t)) {
		DBG_ASSERT(0, "Invalid MAC address");
		return 0;
	}

	memset(&link_stats, 0, sizeof(link_stats));
	ret = ipc_cnu_link_stats_get(&agent, 0, &cnu_id, &link_stats);
	ipc_assert(ret);

	sprintf(stat_str, T("'%6.3f%%;%6.3f;%6.3fdB;%6.3f%%;%6.3f%%;%6.2fdB;%6.2f;%llu;%llu;%llu;%llu;%u'"),
		link_stats.pre_fec, 
		link_stats.bits_carrier,
		link_stats.snr_carrier,
		link_stats.tx_pbs_err,
		link_stats.rx_pbs_err,
		link_stats.avg_att,
		link_stats.avg_txpwr,
		link_stats.txpkt,
		link_stats.txerr,
		link_stats.rxpkt,
		link_stats.rxerr,
		link_stats.valid
	);
	
	wlen += websWrite(wp, T("%s"), stat_str);	

	return wlen;
}


static int asp_clt_list(int eid, webs_t wp, int argc, char_t **argv)
{
	clt_status_and_config_t cltinfos[MAX_CLT_CHANNEL];
	int i, wlen = 0, num, ret;	

	memset(cltinfos, 0, sizeof(cltinfos));

	num = sizeof(cltinfos)/sizeof(cltinfos[0]);
	ret = ipc_clt_config_get(&agent, cltinfos, &num);
	ipc_assert(ret);
	

	for (i = 0; i < num; i ++){
		/*
		1;00:11:22:33:44:55;CLT502-A;1;1;1;32;INT7400 VERSION
		*/
		wlen += websWrite(wp, T("'%d;%s;%s;%d;%d;%d;%d;%d;%d;%d;%s'%s"),
				cltinfos[i].index,
				mac2str(&cltinfos[i].mac),
				cltinfos[i].model,
				cltinfos[i].state,
				cltinfos[i].local,
				cltinfos[i].config.snid,
				cltinfos[i].cnu_num,
				cltinfos[i].config.power,
				cltinfos[i].config.start_freq,
				cltinfos[i].config.end_freq,
				cltinfos[i].version,
				(i == num - 1) ? "" : ",\n");
	}
	return wlen;	
}


static int asp_clt_attribute(int eid, webs_t wp, int argc, char_t **argv)
{
	int ret;
	clt_mgmt_t mgmt;
    #ifdef NSCRTV_HCEXT
    cnu_scalars_t cnu_config;
    #endif /**/
    
	memset(&mgmt, 0, sizeof(mgmt));
	ret = ipc_eoc_mgmt_get(&agent, &mgmt);
	ipc_assert(ret);

    #ifdef NSCRTV_HCEXT    
    ret = ipc_cnu_scalars_get(&agent, &cnu_config);
    ipc_assert(ret);  
	return websWrite(wp, T("'%d','%d', '%d', '%d', '%d', '%d','%d'"), 
		mgmt.refresh_interval, mgmt.anonymous_allow, 
		mgmt.loop_detect, mgmt.template_option, mgmt.extmib_option, cnu_config.vlan_pool_enable,mgmt.access_option);    
    #else 
	return websWrite(wp, T("'%d','%d', '%d', '%d', '%d', '0'"), 
		mgmt.refresh_interval, mgmt.anonymous_allow, 
		mgmt.loop_detect, mgmt.template_option, mgmt.extmib_option);
    #endif /* */    
}





static int asp_client_query(int eid, webs_t wp, int argc, char_t **argv)
{
	ipc_packet_t *pack;
	cnu_infos_t *pinfos;
	int update = 0;
	int i, wlen = 0, ret;

	if(argc < 1) {
		DBG_ASSERT(0, "Invalid argument.");
		return 0;
	}
	
	if(argc > 1) {
		update = strtoul(argv[1], NULL, 0);
	}


	if (update){
		ret = ipc_network_info_refresh(&agent);
		ipc_assert(ret);
	}

	pack = ipc_network_info(agent.ipc_fd, agent.agent, IPC_OP_GET);

	if(pack && (pack->header.ack_status == IPC_STATUS_OK)) {
		pinfos = (cnu_infos_t *)pack->payloads;
		for(i = 0; i < pack->header.payload_num; i ++, pinfos ++) { 
            
#ifdef NSCRTV_HCEXT            
			wlen += websWrite(wp, T("'%d;%d;%s;%d;%d/%d;0;%s;%d;%d;%s;%d;%d;%d;%d/%d;%s'%s"),
					pinfos->clt, pinfos->index, mac2str(&pinfos->mac),
					pinfos->tei,
					pinfos->avgtx,
					pinfos->avgrx, //5
					pinfos->alias,
					pinfos->link,
					pinfos->auth, // cnu_auth_string(pinfos->auth),
					pinfos->username,
					pinfos->device_id,//10
					pinfos->template_id,
					pinfos->online_tm ? time(NULL) - pinfos->online_tm : 0,
					pinfos->atten,
					pinfos->snr,
					pinfos->version,
					(i == pack->header.payload_num - 1) ? "" : ",\n"
					);
 #else 
            wlen += websWrite(wp, T("'%d;%d;%s;%d;%d;%d;%s;%d;%d;%s;%d;%d;%d;%d;%s'%s"),
                    pinfos->clt, pinfos->index, mac2str(&pinfos->mac),
                    pinfos->tei,
                    pinfos->avgtx,
                    pinfos->avgrx, //5
                    pinfos->alias,
                    pinfos->link,
                    pinfos->auth, // cnu_auth_string(pinfos->auth),
                    pinfos->username,
                    pinfos->device_id,//10
                    pinfos->template_id,
                    pinfos->online_tm ? time(NULL) - pinfos->online_tm : 0,
                    pinfos->atten, 
                    pinfos->version,
                    (i == pack->header.payload_num - 1) ? "" : ",\n"
                    );
#endif /* */
		}
	}
	if(pack) free(pack);
	return wlen;
}
/*
static int asp_fs_dir(int eid, webs_t wp, int argc, char_t **argv)
{
	return 0;
}

static int asp_map_name(int eid, webs_t wp, int argc, char_t **argv)
{
	//return websWrite(wp, T("addCfg('%s','%s','%s');\n"), argv[0], argv[1], webs_nvram_safe_get(argv[1]));
	return 0;
}

static int asp_query(int eid, webs_t wp, int argc, char_t **argv)
{
	return 0;
}
*/

static int asp_get_link_status(int eid, webs_t wp, int argc, char_t **argv)
{
	switch_interface_status_t infos[MAX_CLT_ETH_PORTS];
	
	char *spd_string[] = {"10", "100", "1000"};
	int i, wlen = 0, num, ret;

	memset(infos, 0, sizeof(infos));
	num = sizeof(infos)/sizeof(infos[0]);

	ret = ipc_switch_interface_status_get(&agent, NULL, infos, &num);
	ipc_assert(ret);

	for(i = 0; i < num; i ++) {
		wlen += websWrite(wp, T("'%s;%s;%s;%s'%s"),
				infos[i].ifname,
				infos[i].link == 1 ? "UP" : "DOWN",
				infos[i].speed <= 2 ? spd_string[infos[i].speed] : "Unknow",
				infos[i].duplex == 1 ? "FULL" : "HALF",
				(i == num - 1) ? "" : ",\n" 			
				);			
	}
	
	return wlen;
}



static int asp_get_port_mibs(int eid, webs_t wp, int argc, char_t **argv)
{
	switch_interface_mib_t infos[MAX_CLT_ETH_PORTS];
	switch_interface_stats_t stats;	
	int i, wlen = 0, num, ret;
	char in_oct[64], out_oct[64]; 

	memset(infos, 0, sizeof(infos));
	num = sizeof(infos)/sizeof(infos[0]);

	ret = ipc_switch_interface_mibs_get(&agent, NULL, infos, &num);
	ipc_assert(ret);

	for(i = 0; i < num; i ++) {
			//fprintf(stderr, "%s:\n", pack->ifmibs[i].ifname);
			//switch_port_mibs_dump(pack->ifmibs[i].mibs);
			switch_mibs2stats(infos[i].mibs, &stats);
			//switch_port_stats_dump(&stats);

			/*
			Important: websWrite do not support long long options
			*/
			sprintf(in_oct, "%llu", stats.in_octets);
			sprintf(out_oct, "%llu", stats.out_octets);			
			
			wlen += websWrite(wp, T("'%s;%lu;%lu;%lu;%s;%lu;%lu;%lu;%s'%s"),
					infos[i].ifname,
					stats.in_pkts, stats.in_mcast, stats.in_error, in_oct,
					stats.out_pkts, stats.out_mcast, stats.out_drops,out_oct,
					(i == num - 1) ? "" : ",\n");		
	}
	
	return wlen;
}








static int asp_sys_info(int eid, webs_t wp, int argc, char_t **argv)
{
	sys_info_t info;
	int wlen = 0, ret;
	char buffer[16];

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_info_get(&agent, &info);
	ipc_assert(ret);
	
	sprintf(buffer, "%3.2f", info.config_usaged);
	
	wlen += websWrite(wp, T("'%lu','%u','%s','%s','%s','%s','%s','%s','%d', '%d','%d','%d'"),
			info.uptime,
			info.mvlan,
			info.sw_version,
			info.hw_version,
			mac2str(&info.sysmac),
			info.buildtime,
			info.os_version,
			buffer,
			info.rootfs_num,
			info.temperture,
			info.cpu_load,
			info.mem_usaged
			);		
	return wlen;
}

static int asp_sys_time(int eid, webs_t wp, int argc, char_t **argv)
{
	sys_time_t info;
	struct tm tm;	
	int ret;

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_time_get(&agent, &info);
	ipc_assert(ret);

	gmtime_r(&info.time, &tm);

	return websWrite(wp, T("'%d/%d/%d', '%d:%d:%d', '%d;%d;%s'"),
		tm.tm_mon + 1,tm.tm_mday,tm.tm_year+1900,tm.tm_hour,tm.tm_min,tm.tm_sec,
		info.zone, info.ntp_en, info.server);
}

static int asp_sys_security(int eid, webs_t wp, int argc, char_t **argv)
{
	sys_security_t info;
	int wlen = 0, ret;

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_security_get(&agent, &info);
	ipc_assert(ret);
	

	wlen += websWrite(wp, T("'%u','%u','%u','%u','%u', '%u'"),
			info.mvlan,
			info.https_en,
			info.ssh_en,
			info.ssh_port,
			info.telnet_en,
			info.telnet_port
			);	
		
	return wlen;

}

static int asp_sys_snmp(int eid, webs_t wp, int argc, char_t **argv)
{
	sys_snmp_t info;
	int wlen = 0, ret;
#ifdef NSCRTV_EXT	
    nscrtv_snmp_scalars_t scalars;
#endif 

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_snmp_get(&agent, &info);
	ipc_assert(ret);

#ifdef NSCRTV_EXT	
    ret = ipc_nscrtv_snmp_scalars_get(&agent, &scalars);
    ipc_assert(ret);
    info.trap_en = scalars.trap_enable;

    wlen += websWrite(wp, 
          T("'snmp_enable=%u',\n"
            "'snmp_port=%u',\n"
            "'snmp_sysname=%s',\n"
            "'snmp_syscontact=%s',\n"
            "'snmp_syslocation=%s',\n"
            "'snmp_v1v2_limitation=%u',\n"
            "'snmp_trust_ip=%s',\n"
            "'snmp_ro_user=%s',\n"
            "'snmp_ro_user_pwd=%s',\n"
            "'snmp_ro_user_type=%u',\n"
            "'snmp_rw_user=%s',\n"
            "'snmp_rw_user_pwd=%s',\n"
            "'snmp_rw_user_type=%u',\n"
            "'snmp_trap_enable=%u'"),
            info.snmp_en,
            info.snmp_port,
            info.sys_name,
            info.sys_contact,
            info.sys_location,
            info.v1v2_limitation,
            info.v1v2_trust_host,
            info.ro_user,
            info.ro_user_pwd,
            info.ro_user_type,
            info.rw_user,
            info.rw_user_pwd,
            info.rw_user_type,
            info.trap_en
            );  
#else 
	wlen += websWrite(wp, 
		  T("'snmp_enable=%u',\n"
			"'snmp_port=%u',\n"
			"'snmp_sysname=%s',\n"
			"'snmp_syscontact=%s',\n"
			"'snmp_syslocation=%s',\n"
			"'snmp_ro_community=%s',\n"
			"'snmp_rw_community=%s',\n"
			"'snmp_v1v2_limitation=%u',\n"
			"'snmp_trust_ip=%s',\n"
			"'snmp_ro_user=%s',\n"
			"'snmp_ro_user_pwd=%s',\n"
			"'snmp_ro_user_type=%u',\n"
			"'snmp_rw_user=%s',\n"
			"'snmp_rw_user_pwd=%s',\n"
			"'snmp_rw_user_type=%u',\n"
			"'snmp_trap_enable=%u',\n"
			"'snmp_trap_ip=%s',\n"
			"'snmp_trap_port=%u',\n"
			"'snmp_trap_community=%s',\n"
			"'snmp_trap_version=%d'"),
			info.snmp_en,
			info.snmp_port,
			info.sys_name,
			info.sys_contact,
			info.sys_location,
			info.ro_community,
			info.rw_community,
			info.v1v2_limitation,
			info.v1v2_trust_host,
			info.ro_user,
			info.ro_user_pwd,
			info.ro_user_type,
			info.rw_user,
			info.rw_user_pwd,
			info.rw_user_type,
			info.trap_en,
			inet_ntoa(info.trap_server_ip),
			info.trap_port,
			info.trap_community,
			info.trap_version
			);	
#endif 

	return wlen;
}

static int asp_sys_admin(int eid, webs_t wp, int argc, char_t **argv)
{
	sys_admin_t info;
	int wlen = 0, i, ret;

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_admin_get(&agent, &info);
	ipc_assert(ret);
	
	wlen += websWrite(wp, T("'%lu'"), info.idle_time);	
	for (i = 0; i < info.count; i ++){
		wlen += websWrite(wp, T(",'%d;%s;%s'"), info.users[i].enable, info.users[i].name, info.users[i].pwd); 
	}	
	return wlen;
}

static int asp_get_syslog_config(int eid, webs_t wp, int argc, char_t **argv)
{
	syslog_t info;
	int wlen = 0, ret;

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_syslog_get(&agent, &info);
	ipc_assert(ret);

	wlen += websWrite(wp, 
		  T("'remote_enable=%u',\n"
			"'remote_ip=%s',\n"
			"'remote_port=%u'"),
			info.remote_enable,
			inet_ntoa(info.remote_ip),
			info.remote_port
			);		
	return wlen;
}



/*
CLT502;00:11:22:33:44:55;static',
'ok;192.168.0.100;255.255.255.0;192.168.0.1;202.96.125.24;34.45.25.14;0.0.0.0',
'doing;0.0.0.0;0.0.0.0;0.0.0.0;202.96.125.24;34.45.25.14;0.0.0.0;86400;local'

*/
	/*
	struct in_addr ip;
	struct in_addr subnet;
	struct in_addr broadcast;
	struct in_addr gateway;
	struct in_addr dns[MAX_DNS_NUM];
	
		char hostname[MAX_HOSTNAME_SIZE];
		char ifname[IFNAMSIZ];	
		ether_addr_t mac;	
		uint8_t ip_proto;
		netif_param_t netif;
		netif_param_t netif_static;
		uint32_t lease_time; // for dhcp	
		char domain[MAX_DOMAIN_SIZE];			
	*/	


static int asp_sys_networking(int eid, webs_t wp, int argc, char_t **argv)
{
	sys_network_t info;
	int wlen = 0, i, vlen, ret;
	char buffer[64], ip[24], nm[24], gw[24];
	char *dhcp_status;

	memset(&info, 0, sizeof(info));

	ret = ipc_sys_networking_get(&agent, &info);
	ipc_assert(ret);
	
# define DHCP_STATUS_STR_STOP 	"stop"
# define DHCP_STATUS_STR_DOING 	"doing"
# define DHCP_STATUS_STR_OK 	"ok"
# define DHCP_STATUS_STR_FAILED "failed"

	wlen += websWrite(wp, T("'%s;%s;%s',"),
			info.hostname,
			mac2str(&info.mac),
			(info.ip_proto == IP_PROTO_STATIC) ? "static" : "dhcp");	
	
	strcpy(ip, inet_ntoa(info.netif_static.ip));
	strcpy(nm, inet_ntoa(info.netif_static.subnet));
	strcpy(gw, inet_ntoa(info.netif_static.gateway));
	vlen = 0;
	for (i = 0; i < MAX_DNS_NUM; i ++){
		vlen +=sprintf(buffer + vlen, ";%s", inet_ntoa(info.netif_static.dns[i]));
	}
	wlen += websWrite(wp, T("'%s;%s;%s;%s%s',"), "ok", ip, nm, gw, buffer);
	
	if (info.ip_proto == IP_PROTO_STATIC){
		memset(&info.netif, 0, sizeof(info.netif));
		dhcp_status = DHCP_STATUS_STR_STOP;
	}else if (info.netif.ip.s_addr == 0){
		dhcp_status = DHCP_STATUS_STR_DOING;
	}else {
		dhcp_status = DHCP_STATUS_STR_OK;
	}
	
	strcpy(ip, inet_ntoa(info.netif.ip));
	strcpy(nm, inet_ntoa(info.netif.subnet));
	strcpy(gw, inet_ntoa(info.netif.gateway));
	vlen = 0;
	for (i = 0; i < MAX_DNS_NUM; i ++){
		vlen +=sprintf(buffer + vlen, ";%s", inet_ntoa(info.netif.dns[i]));
	}
	wlen += websWrite(wp, T("'%s;%s;%s;%s%s;%lu;%s'"), dhcp_status, ip, nm, gw, buffer, info.lease_time, info.domain);
	return wlen;
}


static int asp_get_web_const(int eid, webs_t wp, int argc, char_t **argv)
{
	system_ack_t ack; 
	sys_info_t sysinfo;
	int cnu_linkup = 0 , cnu_offline = 0;
	static int valid_vendor_info = 0;
	char *p, upper[128];
	
	int ret;
	int nvram_changes = 0;
	int sys_upgrade = 0;
	int vlan_applying = 0;
	time_t ltime;
    
    struct in_addr ip;


	if (!valid_vendor_info){
		ret = ipc_sys_vendor_info_get(&agent, &vendor_info);
		ipc_assert(ret);
		if (ret == IPC_STATUS_OK){
			valid_vendor_info = 1;
		}
	}

	memset(&ack, 0, sizeof(ack));
	
	ret = ipc_system_request_ack(&agent, IPC_SYS_STATUS, 0, &ack);
	ipc_assert(ret);

	ret = ipc_sys_info_get(&agent, &sysinfo);
	ipc_assert(ret);

	cnu_linkup = ipc_cnu_linkup_num(&agent);
	cnu_offline = ipc_cnu_num(&agent) - cnu_linkup ;
//	DBG_PRINTF("cnu_offline is %d", cnu_offline);

	if (ack.status & IPC_SYS_STATUS_NVRAM_CHANGE){
		nvram_changes = 1;
	}
	if (ack.status & IPC_SYS_STATUS_UPGRADING){
		sys_upgrade = 1;
	}
	if (ack.status & IPC_SYS_STATUS_VLAN_APPLYING){
		vlan_applying = 1;
	}	
	

	#if SYS_TIME_UTC
	/*If systime returns the UTC, we should transfer it to localtime 
	  Here, I don't think SYS_TIME_UTC will be set to true in this program
	  Einsn - 2012-01-17
	*/	
	ltime = time(NULL);
	#else
	ltime = time(NULL);
	#endif

	safe_strncpy(upper, vendor_info.vendor_brief, sizeof(upper));
	p = upper;
	while(*p){
		*p = toupper(*p);
		p ++;
	};

	get_if_ipaddr(SYS_NETIF_NAME, &ip);

	return websWrite(wp, T("'%s', '%d', '%d', '%d', '%d', '%lu', '%s', '%s:%s', '%s', '%s %s.','%s','%s','%d','%d','%s'"), 
			vendor_info.web_show_model, nvram_changes, sys_upgrade, vlan_applying, MAX_CLT_CHANNEL, ltime, vendor_info.web_vendor_id,
			!strcmp(vendor_info.web_logo, "none") ? "none" : "default", vendor_info.board_tech,
			vendor_info.web_head_title, vendor_info.copyright_year, upper, inet_ntoa(ip),
			sysinfo.sw_version ,cnu_linkup,cnu_offline,vendor_info.web_site); 
}


static int asp_get_upgrade_state(int eid, webs_t wp, int argc, char_t **argv)
{
	system_ack_t ack; 
	int state = UFILE_STATE_IDLE;
	int error = 0;
	int process = 0;
	int ret;
	char *state_str;

	memset(&ack, 0, sizeof(ack));
	
	ret = ipc_system_request_ack(&agent, IPC_SYS_UPGRADE_STATUS, 0, &ack);
	ipc_assert(ret);
	
	state = ack.process;
	error = ack.error;
	process = ack.percentage;
	
	switch(state)
	{
		case UFILE_STATE_DONE:
			state_str = "ok";
			break;
		case UFILE_STATE_FAILED:
			state_str = "fail";
			break;
		case UFILE_STATE_BOOT_ERASE:
			state_str = "e_boot";
			break;
		case UFILE_STATE_BOOT_WRITE:
		case UFILE_STATE_BOOT_VERIFY:
			state_str = "w_boot";
			break;
		case UFILE_STATE_ROOTFS_ERASE:
			state_str = "e_rootfs";
			break;			
		case UFILE_STATE_ROOTFS_WRITE:
		case UFILE_STATE_ROOTFS_VERIFY:
			state_str = "w_rootfs";
			break;
		case UFILE_STATE_KERNEL_ERASE:
			state_str = "e_kernel";
			break;			
		case UFILE_STATE_KERNEL_WRITE:
		case UFILE_STATE_KERNEL_VERIFY:			
			state_str = "w_kernel";
			break;
		default:			
			state_str = "unknown";
			break;
	}
	
	return websWrite(wp, T("'%s', '%d', '%d'"), state_str, process, error);	
}

static char *status_view_string(int status)
{
	if (status == SV_BUSY){
		return "busy";
	}else if (status == SV_FAILED){
		return "fail";
	}else if (status == SV_DONE){
		return "done";
	}else if (status == SV_LOCKED){
		return "locked";
	}
	return "unknown";
}

static int asp_get_status_view(int eid, webs_t wp, int argc, char_t **argv)
{
	int i, wlen = 0;
	char idstr[8];
	int seq_id = 0;
	eoc_status_view_t info[MAX_CLT_CHANNEL * MAX_CNU_PER_CLT];
	int num, ret;

	if(websQueryString(wp, "seqid", idstr, sizeof(idstr))) {
		seq_id = strtoul(idstr, NULL, 0);
	}	

	num = sizeof(info)/sizeof(info[0]);
	ret = ipc_eoc_handle_status_get(&agent, seq_id, info, &num);
	ipc_assert(ret);

	
	for (i = 0; i < num; i ++){
		wlen += websWrite(wp, T("'%s;%s;%d;%d'%s"),
				mac2str(&info[i].mac),
				status_view_string(info[i].status),
				info[i].clt,
				info[i].cnu,
				(i == num - 1) ? "" : ",\n" 			
				);				
	}	

	return wlen;
}



#ifdef CNU_HISTORY_LIBRARY

static int asp_get_cnu_history(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i;
	ipc_packet_t *pack = NULL;
	cnu_history_t *pinfo;

	pack = ipc_cnu_history(agent.ipc_fd, agent.agent, IPC_OP_GET, 0, NULL);
	if(pack && pack->header.ack_status == IPC_STATUS_OK) {
		pinfo = (cnu_history_t *)pack->payloads;

		for(i = 0; i < pack->header.payload_num; i ++, pinfo ++) {
			wlen += websWrite(wp, T("'%s;%u;%u;%lu;%lu'%s"),
					mac2str(&pinfo->mac),
					pinfo->device_id,
					pinfo->saved,
					pinfo->up_time,
					pinfo->off_time,
					(i == pack->header.payload_num - 1) ? "" : ",\n");
		}
	}
	if(pack) free(pack);
	return wlen;
}



#endif /*CNU_HISTORY_LIBRARY*/



#ifdef PIB_ADVANCED_CONFIG

static void pib_config_default(pib_config_t *pib)
{
	int i;

#define PIB_DEFAULT_PRIORITYS  3,1,2,1
#define PIB_DEFAULT_VLAN_CAPS  1,0,0,1,2,2,3,3
#define PIB_DEFAULT_TTLS  2000,2000,300,300  
#define PIB_DEFAULT_TXBUFS  20,25,45,10  

	uint8_t def_pri[PIB_CAP_CLASS_NUM] = {PIB_DEFAULT_PRIORITYS}; 
	uint16_t def_vlan[8] = {PIB_DEFAULT_VLAN_CAPS};	
	uint16_t def_ttl[PIB_CAP_NUM] = {PIB_DEFAULT_TTLS};
	uint8_t def_txbuf[PIB_CAP_NUM] = {PIB_DEFAULT_TXBUFS};
	
	memset(pib, 0, sizeof(pib_config_t));
	pib->index = -1;
	for (i = 0; i < PIB_CAP_CLASS_NUM; i ++){
		pib->def_pri[i] = def_pri[i];
	}
	pib->vlan_en = 1;
	for (i = 0; i < 8; i ++){
		pib->vlan_pri[i] = def_vlan[i];
	}	

	for (i = 0; i < PIB_CAP_NUM; i ++){
		pib->ttl[i] = def_ttl[i];
	}

	pib->txbuf_en = 0;
	for (i = 0; i < PIB_CAP_NUM; i ++){
		pib->txbuf[i] = def_txbuf[i];
	}

	pib->misc_flags = (PIB_ROUND_ROBIN_SLOT_SELECTION | PIB_1_TO_MANY_BIDIRECTIONAL | PIB_BACKWARD_OPTIMIZE);			
				 
	pib->exclusive_tx = 15;
	pib->exclusive_rx = 20;
}



static int asp_pib_config_query(int eid, webs_t wp, int argc, char_t **argv)
{
	int i, ret, wlen = 0, len;
	char id[64], *p, buf0[128];
	pib_config_t pib;
	pib_config_id_t pib_ids[MAX_PIB_CONFIG_NUM];
	int pib_id, num;
	ether_addr_t pib_mac;

	/*
		no arguments get brief all
	*/	
	if ((argc == 0) || strcmp(argv[0], "id")){
		
		num = sizeof(pib_ids)/sizeof(pib_ids[0]);
		ret = ipc_pib_config_get_ids(&agent, pib_ids, &num);
		if (ret != IPC_STATUS_OK){
			num = 0;
		}
		for (i = 0; i < num; i ++){
		wlen += websWrite(wp, T("'%d;%s;%s'%s"),
				pib_ids[i].index,
				pib_ids[i].name,
				pib_ids[i].desc,
				(i == num - 1) ? "" : ",\n");
		}
		
	} else if (argc > 0){
		pib_config_default(&pib);
		if(websQueryString(wp, argv[0], id, sizeof(id))) {
			/*
			CLTx - 11:22:33:44:55:66
			11:22:33:44:55:66
			*/
			ret = IPC_STATUS_OK;
			p = strchr(id, ':');
			if (p){
				p -= 2;
				if ((p < id) || (hexencode(pib_mac.octet, sizeof(pib_mac.octet), p) != sizeof(ether_addr_t))){
					DBG_ASSERT(0, "Invalid mac address:%s", p);
				}else {
					ret = ipc_pib_config_read_eoc(&agent, &pib_mac, &pib);
					ipc_assert(ret);
				}
			}else {
				pib_id = strtoul(id, NULL, 0);
				ret = ipc_pib_config_query(&agent, pib_id, &pib);
				ipc_assert(ret);
			}
			if (ret != IPC_STATUS_OK){
				pib.index = -2; // unknown ID or mac address or cnu clt is down
			}
		}		

/*
'0;AdvancedConfig1;Description for config 1',
'0;1;2;3;1;0;0;1;0;2;2;3;3',
'2000;2000;300;300;0;20;40;10;30',
'0;0;0;1;1;0;20;30');
*/
		wlen += websWrite(wp, T("'%d;%s;%s',\n"), pib.index,pib.name, pib.desc);

		len = 0;
		for (i = 0; i < PIB_CAP_CLASS_NUM; i ++){
			len += sprintf(buf0 + len, "%u;", pib.def_pri[i]);
		}
		len += sprintf(buf0 + len, "%u;", pib.vlan_en);		
		for (i = 0; i < 8; i ++){
			len += sprintf(buf0 + len, "%u;", pib.vlan_pri[i]);			
		}
		buf0[len - 1] = '\0';// remove the last end char
		
		wlen += websWrite(wp, T("'%s',\n"), buf0);

		len = 0;
		for (i = 0; i < PIB_CAP_NUM; i ++){
			len += sprintf(buf0 + len, "%u;", pib.ttl[i]);
		}
		len += sprintf(buf0 + len, "%u;", pib.txbuf_en);		
		for (i = 0; i < PIB_CAP_NUM; i ++){
			len += sprintf(buf0 + len, "%u;", pib.txbuf[i]);			
		}
		buf0[len - 1] = '\0';// remove the last end char
			
		wlen += websWrite(wp, T("'%s',\n"), buf0);
		wlen += websWrite(wp, T("'%d;%d;%d;%d;%d;%d;%d;%d'"),
			(pib.misc_flags & PIB_ROUND_ROBIN_SLOT_SELECTION) ? 1 : 0,
			(pib.misc_flags & PIB_1_TO_MANY_BIDIRECTIONAL) ? 1 : 0,
			(pib.misc_flags & PIB_UPSTREAM_RTS_CTS_ENABLE) ? 1 : 0,
			(pib.misc_flags & PIB_BIDIRECTION_BURST_DISABLE) ? 1 : 0,
			(pib.misc_flags & PIB_BACKWARD_OPTIMIZE) ? 1 : 0,
			(pib.misc_flags & PIB_OVERRIDE_RESOURCE_OPTIONS) ? 1 : 0,
			pib.exclusive_tx, pib.exclusive_rx);
	}
	
	return wlen;
}


static int asp_get_pib_apply(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i;
	ipc_packet_t *pack = NULL;
	pib_apply_t *pinfo;

	pack = ipc_pib_apply(agent.ipc_fd, agent.agent, IPC_OP_GET, 0, NULL);
	if(pack && pack->header.ack_status == IPC_STATUS_OK) {
		pinfo = (pib_apply_t *)pack->payloads;

		for(i = 0; i < pack->header.payload_num; i ++, pinfo ++) {
			wlen += websWrite(wp, T("'%s;%u'%s"),
					mac2str(&pinfo->mac),
					pinfo->pib_id,
					(i == pack->header.payload_num - 1) ? "" : ",\n");
		}
	}
	if(pack) free(pack);
	return wlen;
}

#endif /*#ifdef PIB_ADVANCED_CONFIG*/


#ifdef SWITCH_STORM_LIMIT
static int asp_get_storm_limit_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int ret;
	switch_storm_limit_t storm_limit;

	memset(&storm_limit, 0, sizeof(storm_limit));

	ret = ipc_switch_storm_limit_get(&agent, &storm_limit);
	ipc_assert(ret);
	

	return websWrite(wp, T("'%u;%u;%u;%u'"), storm_limit.unknown_unicast, 
				storm_limit.unknown_mcast,
				storm_limit.broadcast,
				storm_limit.multicast);
}


#endif /*SWITCH_ENABLE_STORM_LIMIT */



#ifdef EOC_PIBFW_UPGRADE


static int asp_get_fwpib_files(int eid, webs_t wp, int argc, char_t **argv)
{

	if (upload_fw[0] && !file_exist(upload_fw)){
		upload_fw[0] = 0;
	}

	if (upload_pib[0] && !file_exist(upload_pib)){
		upload_pib[0] = 0;
	}
	return websWrite(wp, T("'%s', '%s'"), upload_pib[0] ? upload_pib : "", upload_fw[0] ? upload_fw : "");
}

#endif /* EOC_PIBFW_UPGRADE*/


#ifdef PIB_TONEMAP_CONFIG

static int asp_get_eoc_tonemap(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i, n, len;
	char notch_buffer[16 * EOC_TONEMAP_NOTCHING_MAX_NUM];
	ipc_packet_t *pack = NULL;
	eoc_tonemap_t *pinfo;
	
	pack = ipc_eoc_tonemap(agent.ipc_fd, agent.agent, IPC_OP_GET, 0, NULL);
	if(pack && pack->header.ack_status == IPC_STATUS_OK) {
		pinfo = (eoc_tonemap_t *)pack->payloads;

		for(i = 0; i < pack->header.payload_num; i ++, pinfo ++) {
			notch_buffer[0] = 0;
			len = 0;
			for (n = 0; n < pinfo->notch_num ; n ++){	
				len += sprintf(notch_buffer + len, "%d:%d:%d", 
					pinfo->notch_table[n].fid_start,
					pinfo->notch_table[n].fid_end,
					pinfo->notch_table[n].status
					);
				len += sprintf(notch_buffer + len, "%s", (n == pinfo->notch_num - 1) ? "" : ";");
			}	
			wlen += websWrite(wp, 
						T("'%d;%s;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%s'%s"),
						pinfo->type, 
						pinfo->name,
						pinfo->enabled,
						pinfo->prescalers,
						pinfo->adjustment,
						pinfo->range_enabled,
						pinfo->range_min,
						pinfo->range_max,
						pinfo->notch_enabled,
						pinfo->notch_num_max,
						pinfo->notch_fid_max,
						pinfo->notch_num,
						notch_buffer[0] ? notch_buffer : "",				
					(i == pack->header.payload_num - 1) ? "" : ",\n");
		}
	}
	if(pack) free(pack);
	return wlen;
}


#endif /* PIB_TONEMAP_CONFIG */

#ifdef FOR_CVNCHINA

#define PORTS_NAME ""\
"'eoc;Cable;Eth1;Eth2;Eth3;Eth4'," \
"'eoc;Cable;Ethernet1;Ethernet2;Ethernet3;Ethernet4'," \
"'plc;PLC;Eth1;Eth2;Eth3;Eth4'," \
"'plc;PLC;Ethernet1;Ethernet2;Ethernet3;Ethernet4'"

#else

#define PORTS_NAME ""\
"'eoc;Cable;Eth1;Eth2;Eth3;Eth4'," \
"'eoc;Cable;Ethernet1;Ethernet2;Ethernet3;Ethernet4'," \
"'plc;PLC;Eth1;Eth2;Eth3;Eth4'," \
"'plc;PLC;Ethernet1;Ethernet2;Ethernet3;Ethernet4'"

#endif 

static int asp_get_port_name(int eid, webs_t wp, int argc, char_t **argv)
{
    // there is an argument to be handled.
    return websWrite(wp, T(PORTS_NAME));
}

#ifdef 1

static int Lang(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen;
	FILE *fp;
	char buffer[1024];

// input: text to be translated , system language
// output translated text

	if (system_language() == LANG_EN){
		wlen += websWrite(wp, T("%s"), argv[0]); 		
    }else if (system_language() == LANG_EN){
		value = find_in_file(argv[0], "");
		if (value != NULL){
			wlen += websWrite(wp, T("%s"), value); 
	     }else {
			wlen += websWrite(wp, T("%s"), argv[0]); 
		}		
	}
	return wlen;
}

#endif 

#ifdef NSCRTV_EXT


static int n_asp_get_snmp_community(int eid, webs_t wp, int argc, char_t **argv)
{
    int ret, wlen = 0, i; 
    snmp_community_t infos[NSCRTV_SNMP_COMMUNITY_NUM];
    int num = NSCRTV_SNMP_COMMUNITY_NUM;
    ret = ipc_snmp_community_get(&agent, infos, &num);
    ipc_assert(ret);
    if (ret == IPC_STATUS_OK){
        for (i = 0; i < num; i ++){
			wlen += websWrite(wp, T("'%d;%s;%d'%s"),
				infos[i].index,
				infos[i].value,
				infos[i].access,
				( i == num - 1 ) ? "" : ",\n");
        }
    }

    return wlen;
}

static int n_asp_get_snmp_trap(int eid, webs_t wp, int argc, char_t **argv)
{
    int ret, wlen = 0, i; 
    snmp_trap_t infos[NSCRTV_SNMP_TRAP_NUM];
    int num = NSCRTV_SNMP_TRAP_NUM;
    ret = ipc_snmp_trap_get(&agent, infos, &num);
    ipc_assert(ret);
    if (ret == IPC_STATUS_OK){
        for (i = 0; i < num; i ++){
			wlen += websWrite(wp, T("'%d;%s;%s;%d'%s"),
				infos[i].index,
				inet_ntoa(infos[i].ip),
				infos[i].community,
				infos[i].status,
				( i == num - 1 ) ? "" : ",\n");
        }
    }

    return wlen;
}


#ifdef NSCRTV_HCEXT
static int n_asp_get_vlanpool_config(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_vlanpool_t *pinfo=NULL, *p;	
 	int num, ret=0, slen=0, i ;
    char buffer[4096*4];

    ret = ipc_cnu_vlanpool_get(&agent, &pinfo, &num);
    ipc_assert(ret);

    p = pinfo;
    for (i = 0; i < num; i++){
       vlan_group_sprintf(buffer, p->vlans);
       slen += websWrite(wp, T("'%d;%s;%d;%d;%d;%d;%d;%s'%s"),
           p->index,
           p->name,
           p->enable,
           p->flag, 
           p->count,
           p->available,
           p->priority, 
           buffer,
           (i == num - 1) ? "" : ",\n");
       p = cnu_vlanpool_to_next(p);
     }
    
    if (pinfo) {
        free(pinfo);
        pinfo = NULL;
    }
    
    return ret;
}

#endif 



static int n_asp_get_service_config(int eid, webs_t wp, int argc, char_t **argv)
{
	cnu_service_t *pinfo=NULL;
	
 	int num, ret=0, slen=0, i ;

	num = ipc_cnu_services_num(&agent);

	if ( num > 0 )
	{
		pinfo = (cnu_service_t *) malloc(sizeof(*pinfo) * num);
		if ( pinfo == NULL )
		{
			DBG_ASSERT(0, "malloc(%d)", sizeof(*pinfo) * num);
	        	return 0;
		}
		
		ret = ipc_cnu_service_get(&agent, pinfo, &num);
//		if (HC_IPC_ERROR(ret)) {
//		        goto safe_exit;
//		    }
		 ipc_assert(ret);
				
		 for (i = 0; i < num; i++) {			
			slen += websWrite(wp, T("'%d;%s;%d;%d;%d;%d;%d;%d;%d'%s"),
				pinfo[i].index,
				pinfo[i].name,
				pinfo[i].matching_value,
				pinfo[i].priority, 
				pinfo[i].down_cir,
				pinfo[i].up_cir,
				pinfo[i].down_pir, 
				pinfo[i].up_pir,
				pinfo[i].latency,
				( i == num-1 )?"" :",\n");
		  }
		
	}
/*	 if (pinfo)  {  free(pinfo); }
	 return slen;
*/
//  safe_exit:

    if (pinfo) {
        free(pinfo);
        pinfo = NULL;
    }

 //   HC_IPC_ASSERT(ret);
    return ret;
}


static char * port_vlan_string(int *vlans, int vlan_size)
{
    static char vlan_str[8* NSCRTV_CNU_VLAN_MAX_NUM];
    int i, len = 0;

    vlan_str[0] = 0;

    for (i = 0; i < vlan_size; i ++){
       if (vlans[i]){
            if (len == 0){
                len += sprintf(vlan_str, "%d", vlans[i]);
            }else {
                len += sprintf(vlan_str + len, ",%d", vlans[i]);
            }
       }
    }
    return vlan_str;
}



static int n_asp_get_white_config(int eid, webs_t wp, int argc, char_t **argv)
{
	int wlen = 0, i, ret, num; //wlen : the length of web string 
	char query_id[32];	
    ether_addr_t white_mac;   
	cnu_whitelist_t  *pwhite=NULL , white;

	if (argc < 1){
		DBG_ASSERT(0, "Invalid asp argument");
		return 0;		
	}else if(!strcasecmp(argv[0], "brief")) {
		num = ipc_cnu_whitelists_num(& agent);

		if ( num > 0 )
		{
			pwhite = (cnu_whitelist_t *)malloc(sizeof(*pwhite) * num);
			if ( pwhite == NULL )
			{
				DBG_ASSERT(0, "malloc(%d)",sizeof(*pwhite) * num);
				return 0;
			}
			ret = ipc_cnu_whitelist_get(&agent, pwhite, &num); //ret = 0  , ipc status is ok

			ipc_assert(ret);

			for ( i = 0; i < num; i++ )
			{
			wlen += websWrite(wp,T("'%d;%s;%d;%d;%d;%d;%d;'%s"),
				pwhite[i].index,
				mac2str(&pwhite[i].mac),
				pwhite[i].auth_mode,
				pwhite[i].igmp_snooping,
				pwhite[i].cnu_down_pir,
				pwhite[i].cnu_up_pir,
				pwhite[i].mac_limit,
				( i == num -1 )?"" :",\n");	
			}	
		}
	}
	else if(!strcasecmp(argv[0], "white_mac")){

        // get default values for new whitelist 
        memset(&white, 0, sizeof(white));
		cnu_whitelist_set_default(&white);
        
        if(websQueryString(wp, argv[0], query_id, sizeof(query_id) - 1)){ //if web has string 
            if (strchr(query_id, ':')  //find the position of mac string ':' from the query_id
                && (hexencode(white_mac.octet, sizeof(white_mac), query_id) == sizeof(ether_addr_t))){ 
                // try to load values                
                ret = ipc_cnu_whitelist_query_by_mac(&agent, &white_mac, &white);
                ipc_assert(ret);                
            } 
        }
               
        wlen += websWrite(wp,         
                    T("'%d;%s;%d;%d;%d;%d;%d;%d;%d;%d;%s;%d;%d;%d;%d;%d;%d;%d;%d;%d',\n"),                     
                    white.index,
                    mac2str(&white.mac),
                    white.auth_mode,
                    white.igmp_snooping,
                    white.cnu_down_pir,
                    white.cnu_up_pir,
                    white.mac_limit,
                    white.outlevel,
                    white.autoupgrade,
                    white.admin_status,
                    white.upgrade_file,
                    white.upgrade_type
#ifdef NSCRTV_V3EXT
                    ,white.loop_detect
#else
                    ,0
#endif 
        
#ifdef NSCRTV_SCEXT	
                    ,white.sc_port_mirror_type,
                    white.sc_port_mirror_enable,
                    white.sc_port_mirror_source,
                    white.sc_port_mirror_dest,
                
                    white.sc_loop_detect_enable,
                    white.sc_flow_control,
                    white.sc_aging_time
#else 
                    , 0, 0, 0, 0, 0, 0, 0
#endif 	                            
            );
                
		for(i = 0; i < white.ethcfg.eth_num; i ++) {
            const char *mode[] = {"auto", "10half", "10full", "100half", "100full"};
            const char *port_mode = mode[0];
            
            if (white.ethcfg.eths[i].mode_auto){
                port_mode = mode[0]; 
            }else {
                if ((white.ethcfg.eths[i].mode_speed == 1)
                    && (white.ethcfg.eths[i].mode_duplex == 1)){
                    port_mode = mode[1];     
                }else if ((white.ethcfg.eths[i].mode_speed == 1)
                    && (white.ethcfg.eths[i].mode_duplex == 2)){
                    port_mode = mode[2];                         
                } else if ((white.ethcfg.eths[i].mode_speed == 2)
                    && (white.ethcfg.eths[i].mode_duplex == 1)){
                    port_mode = mode[3];                 
                } else if ((white.ethcfg.eths[i].mode_speed == 2)
                    && (white.ethcfg.eths[i].mode_duplex == 2)){
                    port_mode = mode[4];                     
                }
            }

			wlen += websWrite(wp, T("'%d;%d;%s;%d;%d;%d;%d;%s;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d'%s"),
					i,
					white.ethcfg.eths[i].enable,
					port_mode, // 802.3d
					// vlan and priority
					white.ethcfg.eths[i].pvid,
					white.ethcfg.eths[i].tpid,
					white.ethcfg.eths[i].prio,
					white.ethcfg.eths[i].mode,
					port_vlan_string(white.ethcfg.eths[i].vlan_id, sizeof(white.ethcfg.eths[i].vlan_id)/sizeof(white.ethcfg.eths[i].vlan_id[0])),
			        //white.ethcfg.eths[i].vlan_untagged  TODO
			
			        // broadcast storm filter
					white.ethcfg.eths[i].storm_bcast_enable,
					white.ethcfg.eths[i].storm_bcast_threshold,
					white.ethcfg.eths[i].storm_mcast_enable,
					white.ethcfg.eths[i].storm_mcast_threshold,
					white.ethcfg.eths[i].storm_ucast_enable,
					white.ethcfg.eths[i].storm_ucast_threshold,

                    // service
					white.ethcfg.eths[i].service_id, // service id
#ifdef NSCRTV_HCEXT            
                    // nscrtv_hcext					
					white.ethcfg.eths[i].flow_ctrl,
                    white.ethcfg.eths[i].vlanpool_id,
                    white.ethcfg.eths[i].vlanpool_pvid, // read-only
#else 
#ifdef NSCRTV_SCEXT
                    (white.sc_flow_control & (3 << 2*i)) ? 1 : 0, 0, 0, 
#else
                    0,0,0,
#endif                     
#endif /* */										
					(i == white.ethcfg.eth_num - 1) ? "" : ",\n" );
		}
	}
	
    if (pwhite) {
        free(pwhite);
	    pwhite = NULL;
    }
	return wlen;	
}

#else 
// a dummy handle
static int n_asp_get_white_config(int eid, webs_t wp, int argc, char_t **argv)
{
    return 0;
}


#endif  /* NSCRTV_EXT */



static const struct {
	char *name;
	int (*fn)(int ejid, webs_t wp, int argc, char_t **argv);
}
asp_func_table[] = {
//		{"CGI_MAP_NAME",		asp_map_name},/*to be del*/	
		//{"CGI_GET_DHCP_INFO",	asp_get_dhcp_info},
		{"CGI_GET_VARIABLE",	asp_get_variable},
		{"CGI_GET_WEB_CONST",	asp_get_web_const},
		{"CGI_GET_UPGRADE_STATE", asp_get_upgrade_state},
//		{"CGI_QUERY",			asp_query},/*to be del*/	
		{"CGI_GET_LINK_STATUS",	asp_get_link_status},		
		{"CGI_GET_PORT_MIBS",	asp_get_port_mibs},
		//{"CGI_QUERY_LINK_STATUS",	asp_query_link_status},/*to be del*/
		{"CGI_CLIENT_QUERY",	asp_client_query},
		//{"CGI_FS_DIR",			asp_fs_dir},/*to be del*/	
		//{"CGI_STA_CABLE_QUERY",	asp_sta_cable_query},
		//{"CGI_TEMPLATE_QUERY",	asp_template_query},
		//{"CGI_USER_QUERY",		asp_user_query},/*to be del*/
		{"CGI_GET_SYSLOG",		asp_get_syslog},
		{"CGI_DUMP_CONFIG",		asp_dump_sysconfig},
		{"CGI_DUMP_DBGINFO",		asp_dump_debuginfo},		
		{"CGI_GET_SYSLOG_CFG",	asp_get_syslog_config},		
		//{"CGI_CNU_STATUS",		asp_cnu_status},
		{"CGI_CNU_INFO",    	asp_cnu_info},
		{"CGI_CNU_MIBS",    	asp_cnu_mibs},		
		{"CGI_CNU_LINK_STATS",  asp_cnu_link_stats},
		{"CGI_CNU_CONFIG_DUMP",  asp_cnu_config_dump},
      	       {"CGI_CNU_BRIDGE_DUMP",  asp_cnu_bridge_dump},
		{"CGI_CLT_BRIDGE_DUMP", asp_clt_bridge_dump},
		{"CGI_CLT_LIST",		asp_clt_list},	
		{"CGI_CLT_ATTRIBUTE",	asp_clt_attribute},			
		{"CGI_GET_ETH_CONFIG",	asp_get_ethernet_config},	
		{"CGI_GET_VLANIF_CONFIG",		asp_get_vlan_interface_config},		
		{"CGI_GET_VLAN_CONFIG",			asp_get_vlan_config},
		{"CGI_GET_VLAN_MODE_CONFIG", 	asp_get_vlan_mode_config},
		{"CGI_GET_USER_CONFIG", asp_get_user_config},
		{"CGI_GET_DEVINFO", 	asp_get_devinfo},
		{"CGI_GET_TEMPLATES",	asp_get_templates},		
		{"CGI_SYS_INFO",		asp_sys_info},
		{"CGI_SYS_TIME",		asp_sys_time},
		{"CGI_SYS_SECURITY",	asp_sys_security},
		{"CGI_SYS_SNMP",		asp_sys_snmp},						
		{"CGI_SYS_ADMIN",		asp_sys_admin}, 	
		{"CGI_SYS_IP",			asp_sys_networking},
		{"CGI_GET_STATUS_VIEW",	asp_get_status_view},
        {"CGI_GET_PORT_NAME", asp_get_port_name},	
		{"L",L},
        
#ifdef NSCRTV_EXT
#ifdef NSCRTV_HCEXT
        {"CGI_GET_VLANPOOL_CONFIG", n_asp_get_vlanpool_config},
#endif         
		{"CGI_GET_SERVICE_CONFIG", n_asp_get_service_config},
		{"CGI_GET_WHITE_CONFIG", n_asp_get_white_config},
        {"CGI_SYS_SNMP_TRAP", n_asp_get_snmp_trap},
        {"CGI_SYS_SNMP_COMMUNITY", n_asp_get_snmp_community},	
#else 
        {"CGI_GET_WHITE_CONFIG", n_asp_get_white_config},
#endif  /*NSCRTV_EXT*/

		//{"CGI_GET_FILES",		asp_get_files},	
#ifdef CNU_HISTORY_LIBRARY
		{"CGI_GET_CNU_HISTORY", asp_get_cnu_history},
#endif /**/

#ifdef PIB_ADVANCED_CONFIG
		{"CGI_PIB_CONFIG_QUERY", asp_pib_config_query},
		{"CGI_GET_PIB_APPLY",   asp_get_pib_apply},
#endif /*PIB_ADVANCED_CONFIG*/

#ifdef SWITCH_STORM_LIMIT
		{"CGI_GET_STORM_LIMIT", asp_get_storm_limit_config},
#endif /*SWITCH_STORM_LIMIT */

#ifdef EOC_PIBFW_UPGRADE
		{"CGI_FWPIB_FILE", 		asp_get_fwpib_files},
#endif /* EOC_PIBFW_UPGRADE */

#ifdef PIB_TONEMAP_CONFIG
		{"CGI_EOC_TONEMAP", 	asp_get_eoc_tonemap},
#endif /* PIB_TONEMAP_CONFIG */
		{NULL,					NULL},
};


void websAspFuncDefine(void)
{
	int i;

	read_language_file(LANG_CN_PATH, lang_cn_head);
	read_language_file(LANG_JP_PATH, lang_jp_head);
		
	
#ifdef EOC_PIBFW_UPGRADE	
	memset(upload_pib, 0, sizeof(upload_pib));
	memset(upload_fw, 0, sizeof(upload_fw));
#endif /*EOC_PIBFW_UPGRADE*/	
	for(i = 0; asp_func_table[i].name; i ++)
		websAspDefine(asp_func_table[i].name, asp_func_table[i].fn);
	//webs_nvram_init();
}


#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <mosquitto.h>

static int run = -1;

static void signal_handler(int s)
{
	run = 0;
}

static void prop_test(const mosquitto_property *props)
{
	mosquitto_property *dest = NULL;

	if(mosquitto_property_copy_all(&dest, props)){
		exit(1);
	}
	mosquitto_property_free_all(&dest);
}

static void msg_test(const struct mosquitto_message *msg)
{
	struct mosquitto_message *dest = NULL;

	if(mosquitto_message_copy(dest, msg)){
		exit(1);
	}
	mosquitto_message_free(&dest);
}

static void on_pre_connect(struct mosquitto *mosq, void *obj)
{
}

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	char *command = obj;
	int mid;
	mosquitto_property *props = NULL;

	if(rc || obj != mosquitto_userdata(mosq)){
		exit(1);
	}else{
		//mosquitto_disconnect(mosq);
	}
	if(command){
		if(!strcmp(command, "subscribe-2")){
			mosquitto_subscribe_v5(mosq, &mid, "test/subscribe", 2, 0, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "subscribe-1")){
			mosquitto_subscribe_v5(mosq, &mid, "test/subscribe", 1, 0, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "subscribe-0")){
			mosquitto_subscribe_v5(mosq, &mid, "test/subscribe", 0, 0, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "subscribe-multiple")){
			char *subs[] = {"test/subscribe1", "test/subscribe2"};
			mosquitto_subscribe_multiple(mosq, &mid, 2, subs, 2, 0, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "unsubscribe")){
			mosquitto_unsubscribe_v5(mosq, &mid, "test/subscribe", props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "unsubscribe-multiple")){
			char *subs[] = {"test/subscribe1", "test/subscribe2"};
			mosquitto_unsubscribe_multiple(mosq, &mid, 2, subs, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "publish-2")){
			mosquitto_publish_v5(mosq, &mid, "test/publish", strlen("message"), "message", 2, 0, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "publish-1")){
			mosquitto_publish_v5(mosq, &mid, "test/publish", strlen("message"), "message", 1, 0, props);
			if(mid != 1){
				exit(1);
			}
		}else if(!strcmp(command, "publish-0")){
			mosquitto_publish_v5(mosq, &mid, "test/publish", strlen("message"), "message", 0, 0, props);
			if(mid != 1){
				exit(1);
			}
		}
	}
}

static void on_connect_with_flags(struct mosquitto *mosq, void *obj, int rc, int flags)
{
}

static void on_connect_v5(struct mosquitto *mosq, void *obj, int rc, int flags, const mosquitto_property *props)
{
	prop_test(props);
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)mosq;
	(void)obj;

	run = rc;
}

static void on_disconnect_v5(struct mosquitto *mosq, void *obj, int rc, const mosquitto_property *props)
{
	(void)mosq;
	(void)obj;

	prop_test(props);

	run = rc;
}

static void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
}

static void on_publish_v5(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *props)
{
	prop_test(props);
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	msg_test(msg);
}

static void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *props)
{
	msg_test(msg);
	prop_test(props);
}

static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int tot = 0;
	for(int i=0; i<qos_count; i++){
		tot += granted_qos[i];
	}
}

static void on_subscribe_v5(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props)
{
	int tot = 0;
	for(int i=0; i<qos_count; i++){
		tot += granted_qos[i];
	}
	prop_test(props);
}

static void on_unsubscribe(struct mosquitto *mosq, void *obj, int reason_code)
{
}

static void on_unsubscribe_v5(struct mosquitto *mosq, void *obj, int reason_code, const mosquitto_property *props)
{
	prop_test(props);
}

static void on_log(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	if(str == NULL){
		exit(1);
	}
	int i = strlen(str);
}


static void setup_signal_handler(void)
{
	struct sigaction act = { 0 };

	act.sa_handler = &signal_handler;
	if(sigaction(SIGTERM, &act, NULL) < 0) {
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct mosquitto *mosq;
	int port;
	int proto_ver;
	bool clean_start;
	char *command = NULL;

	if(argc < 4){
		return 1;
	}
	setup_signal_handler();

	port = atoi(argv[1]);
	proto_ver = atoi(argv[2]);
	clean_start = strcasecmp(argv[3], "false");
	if(argc == 5){
		command = argv[4];
	}

	mosquitto_lib_init();

	mosq = mosquitto_new("fuzzish", clean_start, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_user_data_set(mosq, command);

	mosquitto_pre_connect_callback_set(mosq, on_pre_connect);

	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_connect_with_flags_callback_set(mosq, on_connect_with_flags);
	mosquitto_connect_v5_callback_set(mosq, on_connect_v5);

	mosquitto_disconnect_callback_set(mosq, on_disconnect);
	mosquitto_disconnect_v5_callback_set(mosq, on_disconnect_v5);

	mosquitto_publish_callback_set(mosq, on_publish);
	mosquitto_publish_v5_callback_set(mosq, on_publish_v5);

	mosquitto_message_callback_set(mosq, on_message);
	mosquitto_message_v5_callback_set(mosq, on_message_v5);

	mosquitto_subscribe_callback_set(mosq, on_subscribe);
	mosquitto_subscribe_v5_callback_set(mosq, on_subscribe_v5);

	mosquitto_unsubscribe_callback_set(mosq, on_unsubscribe);
	mosquitto_unsubscribe_v5_callback_set(mosq, on_unsubscribe_v5);

	mosquitto_log_callback_set(mosq, on_log);

	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, proto_ver);

	rc = mosquitto_connect(mosq, "localhost", port, 60);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	while(run == -1){
		mosquitto_loop(mosq, -1, 1);
	}

	mosquitto_destroy(mosq);

	mosquitto_lib_cleanup();
	return run;
}

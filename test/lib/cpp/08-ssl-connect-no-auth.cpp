#include <cassert>
#include <mosquitto/libmosquittopp.h>
#include "path_helper.h"

static int run = -1;

class mosquittopp_test : public mosqpp::mosquittopp
{
	public:
		mosquittopp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
};

mosquittopp_test::mosquittopp_test(const char *id) : mosqpp::mosquittopp(id)
{
}

void mosquittopp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		disconnect();
	}
}

void mosquittopp_test::on_disconnect(int rc)
{
	run = rc;
}


int main(int argc, char *argv[])
{
	struct mosquittopp_test *mosq;

	assert(argc == 2);
	int port = atoi(argv[1]);

	mosqpp::lib_init();

	mosq = new mosquittopp_test("08-ssl-connect-no-auth");

	char cafile[4096];
	cat_sourcedir_with_relpath(cafile, "/../../ssl/all-ca.crt");
	mosq->tls_set(cafile);
	mosq->connect("localhost", port, 60);

	while(run == -1){
		mosq->loop();
	}
	delete mosq;

	delete mosq;
	mosqpp::lib_cleanup();

	return run;
}

#include <stdio.h>
#include <string.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/brng.h>>
#include <bee2/core/err.h>
#include <bee2/core/util.h>
#define cmd_t octet 

#define PRIV_KEY_SIZE 64

#define ARG_KEY "-k"
#define ARG_SIG_FILE "-s"
#define ARG_EXEC "--executable"
#define ARG_VFY "vfy"
#define ARG_SIGN "sign"
#define ARG_PRINT "print"

#define COMMAND_UNKNOWN (cmd_t)0
#define COMMAND_VFY (cmd_t)1
#define COMMAND_SIGN (cmd_t)2
#define COMMAND_PRINT (cmd_t)3

/*
*******************************************************************************
Утилита sig

Функционал:
- построение ЭЦП;
- проверка ЭЦП;
- печать ЭЦП.

Примеры:
  bee2cmd sig sign -s signature.bin -k private_key.bin file_to_sign.pdf
  bee2cmd sig vfy  -s signature.bin -k public_key.bin file_to_sign.pdf
  bee2cmd sig print signature.bin

  bee2cmd sig sign -k private_key.bin --executable file_to_sign.exe
  bee2cmd sig vfy  -k public_key.bin --executable file_to_sign.exe
  bee2cmd sig print --executable file_to_sign.exe

*******************************************************************************
*/

static const char _name[] = "sig";
static const char _descr[] = "make and verify digital signature";

bool_t has_arg(int argc, char* argv[], const char* arg){
	for (int i = 0; i< argc; i++){
		if (strcmp(arg,argv[i])==0)
			return TRUE;
	}
	return FALSE;
}

cmd_t get_command(const char* arg) {
    if (!arg){
        return COMMAND_UNKNOWN;
    }

    const char* args[]      = {ARG_VFY,       ARG_SIGN,       ARG_PRINT };
    const cmd_t commands[]  = {COMMAND_VFY,   COMMAND_SIGN,   COMMAND_PRINT};
    const int count = 3;
    for (int i =0; i<count; i++){
        if (strcmp(arg, args[i])==0){
            return commands[i];
        }
    }
    return COMMAND_UNKNOWN;
}

const char* findArg(int argc,const char* argv[], const char *argName){
       
    for (int i = 0; i < argc-1; i++){
        if (strcmp(argv[i], argName) == 0){
            return argv[i+1];
        }
    }

    return NULL;
}

typedef struct
{
	const octet* X;		/*< дополнительное слово */
	size_t count;		/*< размер X в октетах */
	size_t offset;		/*< текущее смещение в X */
	octet state_ex[];	/*< состояние brngCTR */
} brng_ctrx_st;

static size_t brngCTRX_keep()
{
	return sizeof(brng_ctrx_st) + brngCTR_keep();
}

static void brngCTRXStart(const octet key[32], const octet iv[32],
	const void* X, size_t count, void* state)
{
	brng_ctrx_st* s = (brng_ctrx_st*)state;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	ASSERT(count > 0);
	ASSERT(memIsValid(s->state_ex, brngCTR_keep()));
	brngCTRStart(s->state_ex, key, iv);
	s->X = (const octet*)X;
	s->count = count;
	s->offset = 0;
}

static void brngCTRXStepR(void* buf, size_t count, void* stack)
{
	brng_ctrx_st* s = (brng_ctrx_st*)stack;
	octet* buf1 = (octet*)buf;
	size_t count1 = count;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	// заполнить buf
	while (count1)
		if (count1 < s->count - s->offset)
		{
			memCopy(buf1, s->X + s->offset, count1);
			s->offset += count1;
			count1 = 0;
		}
		else
		{
			memCopy(buf1, s->X + s->offset, s->count - s->offset);
			buf1 += s->count - s->offset;
			count1 -= s->count - s->offset;
			s->offset = 0;
		}
	// сгенерировать
	brngCTRStepR(buf, count, s->state_ex);
}

static int sigUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  sig sign [--executable] [-s <sig_name>] -k <private_key> <file_name>\n"
		"    sign <file_name> with <private_key> and write signature to <sig_name>"
        "    if file is not executable or embed it otherwise\n"
		"  sig vfy [--executable] [-s <sig_name>] -k <public_key> <file_name>\n"
		"    verify signature of <file_name>, that is stored in <sig_name> if file"
        "    is not executable and embeded otherwice\n"
		"  sig print [--executable] <file_with_signature>\n"
		"    print the signature\n",
		_name, _descr
	);
	return -1;
}


static char* sigCurveName(int hid){
	switch (hid)
	{
	case 128:
		return "1.2.112.0.2.0.34.101.45.3.1";
	case 192:
		return "1.2.112.0.2.0.34.101.45.3.2";
	case 256:
		return "1.2.112.0.2.0.34.101.45.3.3";
	default:
		return NULL;
	}
}

static err_t sigSign(const char* file_name, const char* sig_name, const char* key_name){
	octet key[32];
	octet hash[32];
	octet sig[96];
	char* curve;
	FILE* key_file;
	FILE* sig_file;
	size_t key_size;
	bign_params params;
	err_t error;
	octet oid_der[128];
	size_t oid_len;
	octet brng_state[1024];

	ASSERT(sizeof(brng_state) >= brngCTRX_keep());

	key_file = fopen(key_name, "rb");

	if (!key_file){
		printf("%s: FAILED [open]\n", key_name);
		return ERR_FILE_OPEN;
	}
	key_size = fread(key,1, sizeof(key), key_file);
	fclose(key_file);

	bsumHashFile(hash, key_size, file_name);
	curve = sigCurveName(key_size*8);
	if (curve == NULL){
		printf("FAILED: error key size: %d",key_size * 8);
		return ERR_BAD_LENGTH;
	}
	bignStdParams(&params,curve);

	if (error = bignStdParams(&params, curve) != ERR_OK)
		return error;
	if (error = bignValParams(&params) != ERR_OK)
		return error;

	oid_len = sizeof(oid_der);
	if (error = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81") != ERR_OK)
		return error;

	brngCTRXStart(beltH() + 128, beltH() + 128 + 64,
	    beltH(), 8 * 32, brng_state);

	if (error = bignSign(sig, &params, oid_der, oid_len,hash, key, brngCTRXStepR, brng_state) != ERR_OK)
		return error;

	if (sig_name == NULL){
		printf("Not implemented\n");
		return ERR_OK;
	}

	sig_file = fopen(sig_name, "wb");
	if (!sig_file){
		printf("%s: FAILED [open]\n", sig_name);
		return ERR_FILE_OPEN;
	}

	fwrite(sig, 1, key_size*3, sig_file);
	fclose(sig);
	printf("Sig saved to %s\n",sig_name);
	return ERR_OK;
}

static err_t sigVfy(const char* file_name, const char* sig_name, const char* key_name){
	octet key[32];
	octet hash[32];
	octet sig[96];
	char* curve;
	FILE* key_file;
	FILE* sig_file;
	size_t key_size;
	bign_params params;
	err_t error;
	octet oid_der[128];
	size_t oid_len;
	
	key_file = fopen(key_name, "rb");

	if (!key_file){
		printf("%s: FAILED [open]\n", key_name);
		return ERR_FILE_OPEN;
	}
	key_size = fread(key,1, sizeof(key), key_file);
	bsumHashFile(hash, key_size, file_name);

	curve = sigCurveName(key_size);
	if (curve == NULL){
		printf("FAILED: error key size : %d", key_size);
		return ERR_BAD_LENGTH;
	}
	bignStdParams(&params,curve);

	if (error = bignStdParams(&params, curve) != ERR_OK)
		return error;

	if (error = bignValParams(&params) != ERR_OK)
		return error;

	oid_len = sizeof(oid_der);
	if (error = bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81") != ERR_OK)
		return error;

	sig_file = fopen(sig_name, "rb");
	if (!sig_file){
		printf("%s: FAILED [open]\n", sig_name);
		return ERR_FILE_OPEN;
	}

	fread(sig, 1, key_size*3, sig_file);

	return bignVerify(&params,oid_der,oid_len,hash, sig, key);
}

static err_t sigPrint(char* sig_name){
	octet sig[96];
	char hex_sig[96*2];
	size_t sig_len;
	FILE* sig_file;

	sig_file = fopen(sig_name, "rb");
	if (!sig_file){
		printf("%s: FAILED [open]\n", sig_name);
		return ERR_FILE_OPEN;
	}
	
	sig_len = fread(sig, 1, 96, sig_file);
	
	for (size_t i = 0; i < sig_len; i++)
	{
		hexFrom(hex_sig,sig,sig_len);
	}
	printf(hex_sig);
}

int sigMain(int argc, char* argv[]){
	err_t code;
	const char* key_name;
	const char* sig_name;
	const char* file_name;
	// справка
	if (argc < 3)
		return sigUsage();
	
	cmd_t cmd = get_command(argv[1]);


	if (cmd == COMMAND_SIGN || cmd == COMMAND_VFY){
		key_name = findArg(argc,argv, ARG_KEY);
		if (!key_name){
			printf("%s argument is required", ARG_KEY);
			return ERR_CMD_PARAMS; 
		}
		sig_name = findArg(argc, argv, ARG_SIG_FILE);
		if (!sig_name && !has_arg(argc, argv, ARG_EXEC)){
			printf("One of arguments %s, %s is requred", ARG_SIG_FILE, ARG_EXEC);
			return ERR_CMD_PARAMS;
		}
	}

	switch (cmd)
	{
	case COMMAND_SIGN:
		code = sigSign(argv[argc-1],sig_name, key_name);
		break;
	case COMMAND_VFY:
		code = sigVfy(argv[argc-1], sig_name, key_name);
		break;
	case COMMAND_PRINT:
		code = sigPrint(argv[argc-1]);
		break;
	default:
		return sigUsage();
	}

	if (code != ERR_OK){
		printf("ERROR %d\n", code);
	}
	return (code == ERR_OK) ? 0 : -1;
}

err_t sigInit(){
	return cmdReg(_name, _descr, sigMain);
}
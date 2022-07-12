#include <stdio.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/core/err.h>
#include <bee2/core/util.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/hex.h>
#include "../cmd.h"

#define cmd_t octet

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
static const char _descr[] = "sign and verify files";

static int sigUsage(){
	printf(
 		"bee2cmd/%s: %s\n"
 		"Usage:\n"
 		"  sig sign [--executable] [-s <sig_name>] -k <private_key> <file_name>\n"
 		"    sign <file_name> with <private_key> and write signature to <sig_name>"
        "    if file is not executable or embed it otherwise\n"
 		"  sig vfy [--executable] [-s <sig_name>] -k <public_key> <file_name>\n"
 		"    verify signature of <file_name>, that is stored in <sig_name> if file"
        "    is not executable and embedded otherwice\n"
 		"  sig print [--executable] <file_with_signature>\n"
 		"    print the signature\n", 
		_name, _descr
	);
	return -1;
}

static cmd_t getCommand(const char* arg) {
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

const char* findArgument(int argc,char* argv[], const char *argName){
       
    for (int i = 0; i < argc-1; i++){
        if (strcmp(argv[i], argName) == 0){
            return argv[i+1];
        }
    }

    return NULL;
}

const char* sigCurveName(size_t hid){
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

const char* sigHashAlgIdentifier(size_t hid){
	switch (hid)
	{
	case 128:
		return "1.2.112.0.2.0.34.101.31.81";
	case 192:
		return "1.2.112.0.2.0.34.101.77.12";
	case 256:
		return "1.2.112.0.2.0.34.101.77.13";
	default:
        return NULL;
	}
}

int bsumHashFileWithEndPadding(octet hash[], size_t hid, const char* filename, unsigned endPadding)
{
	size_t file_size;
	size_t total_readed;
	bool_t eof_reached;
	FILE* fp;
	octet state[4096];
	octet buf[4096];
	size_t count;
	// открыть файл
	fp = fopen(filename, "rb");

	if (!fp)
	{
		printf("%s: FAILED [open]\n", filename);
		return -1;
	}

	if (endPadding > 0){
		fseek(fp,0L,SEEK_END);
		file_size = ftell(fp);
		rewind(fp);
	} else {
		file_size = 0;
	}
	
	total_readed = 0;
	eof_reached = FALSE;

	// хэшировать
	ASSERT(beltHash_keep() <= sizeof(state));
	ASSERT(bashHash_keep() <= sizeof(state));
	hid ? bashHashStart(state, hid / 2) : beltHashStart(state);
	while (!eof_reached)
	{
		count = fread(buf, 1, sizeof(buf), fp);

		if (endPadding > 0 && total_readed + count > file_size - endPadding){
			count = total_readed + count - file_size + endPadding;
			eof_reached = TRUE;
		}
		if (count == 0)
		{
			if (ferror(fp))
			{
				fclose(fp);
				printf("%s: FAILED [read]\n", filename);
				return -1;
			}
			break;
		}
		hid ? bashHashStepH(buf, count, state) : 
			beltHashStepH(buf, count, state);

		total_readed += count;
	}
	// завершить
	fclose(fp);
	hid ? bashHashStepG(hash, hid / 8, state) : beltHashStepG(hash, state);
	return 0;
}

static err_t sigSign(const char* file_name, const char* sig_file_name, const char* key_name){
	octet key[64];
	octet hash[64];
	octet sig[96];
	size_t sig_size;
	size_t end_padding;
	const char* curve;
	FILE* key_file;
	FILE* sig_file;
	size_t key_size;
	bign_params params;
	err_t error;
	octet oid_der[128];
	size_t oid_len;
	octet* t;
	size_t t_len;

	key_file = fopen(key_name, "rb");

	if (!key_file){
		printf("%s: FAILED [open]\n", key_name);
		return ERR_FILE_OPEN;
	}
	key_size = fread(key,1, sizeof(key), key_file);
	sig_size = key_size*3/2;

	fclose(key_file);

    memSetZero(hash,sizeof(hash));

	if (sig_file_name){
		end_padding = 0;
	} else {
		end_padding = sig_size+1;
	}

	if (bsumHashFileWithEndPadding(hash, key_size == 32 ? 0 : key_size*8, file_name, end_padding) != 0){
		printf("FAILED: an error occured while hashing the file\n");
		return ERR_BAD_HASH;
	}	
	
	curve = sigCurveName(key_size*4);
	if (curve == NULL){
		printf("FAILED: incorrect key size: %lu\n", key_size * 8);
		return ERR_BAD_PRIVKEY;
	}

	error = bignStdParams(&params, curve);
	ERR_CALL_CHECK(error);

	error = bignValParams(&params);
	ERR_CALL_CHECK(error);

	oid_len = sizeof(oid_der);
	error = bignOidToDER(oid_der, &oid_len, sigHashAlgIdentifier(key_size*4));
	ERR_CALL_CHECK(error);

    memSetZero(sig,sizeof(sig));

	if (rngIsValid())
		rngStepR(t, t_len = key_size, 0);
	else
		t_len = 0;

	error = bignSign2(sig, &params, oid_der, oid_len,hash, key, t, t_len);
	ERR_CALL_CHECK(error);

	if (sig_file_name) {
        sig_file = fopen(sig_file_name, "wb");
        if (!sig_file) {
            printf("%s: FAILED [open]\n", sig_file_name);
            return ERR_FILE_OPEN;
        }
    }
    else {
        sig_file = fopen(file_name, "a");
        if (!sig_file){
            printf("%s: FAILED [open]\n", file_name);
            return ERR_FILE_OPEN;
        }
    }
    fwrite(sig, 1, sig_size, sig_file);
	fwrite(&sig_size, 1, 1, sig_file);
    fclose(sig_file);
    printf("SUCCESS: signature saved to %s\n", sig_file_name ? sig_file_name : file_name);

	return ERR_OK;
}

static err_t sigVfy(const char* file_name, const char* sig_file_name, const char* key_name) {
	octet key[128];
	octet hash[64];
	octet sig[96];
	const char* curve;
	FILE* key_file;
	FILE* sig_file;
	size_t key_size;
	size_t sig_size;
	bign_params params;
	err_t error;
	octet oid_der[128];
	size_t oid_len;
	size_t end_padding;
	size_t file_size;
	const char* file_with_sig_file_name;

	file_with_sig_file_name = sig_file_name ? sig_file_name : file_name;

	key_file = fopen(key_name, "rb");

	if (!key_file){
		printf("%s: FAILED [open]\n", key_name);
		return ERR_FILE_OPEN;
	}

	key_size = fread(key,1, sizeof(key), key_file);
	sig_size =  key_size*3/4;
	if (sig_file_name){
		end_padding = 0;
	} else {
		end_padding = sig_size+1;
	}

	if (bsumHashFileWithEndPadding(hash, key_size == 64 ? 0 : key_size*4, file_name, end_padding) != 0){
		printf("FAILED: an error occured while hashing the file\n");
		return ERR_BAD_HASH;
	}

	curve = sigCurveName(key_size*2);
	if (curve == NULL){
		printf("FAILED: incorrect key size : %lu\n", key_size*8);
		return ERR_BAD_PUBKEY;
	}

	error = bignStdParams(&params, curve);
	ERR_CALL_CHECK(error);

	error = bignValParams(&params);
	ERR_CALL_CHECK(error);

	oid_len = sizeof(oid_der);
	error = bignOidToDER(oid_der, &oid_len, sigHashAlgIdentifier(key_size*2));
	ERR_CALL_CHECK(error);

	sig_file = fopen(file_with_sig_file_name, "rb");
	if (!sig_file){
		printf("%s: FAILED [open]\n", file_with_sig_file_name);
		return ERR_FILE_OPEN;
	}

	if (!sig_file_name){
		fseek(sig_file,0L,SEEK_END);
		file_size = ftell(sig_file);
		fseek(sig_file, file_size - sig_size-1, SEEK_SET);
	} 

	fread(sig, 1, sig_size, sig_file);
	
	error = bignVerify(&params,oid_der,oid_len,hash, sig, key);

	if (error == ERR_OK)
		printf("SUCCESS: signature is correct\n");
	else printf("FAILED: %s", errMsg(error));

    return error;
}

static err_t sigPrint(char* sig_file_name, bool_t is_binary){
	octet sig[96];
	char hex_sig[96*2+1];
	size_t sig_len;
	u8 sig_len_bytes;
	size_t file_size;
	FILE* sig_file;

	sig_file = fopen(sig_file_name, "rb");
	if (!sig_file){
		printf("%s: FAILED [open]\n", sig_file_name);
		return ERR_FILE_OPEN;
	}

	if (is_binary){
		fseek(sig_file,0L,SEEK_END);
		file_size = ftell(sig_file);
		fseek(sig_file, file_size-1, SEEK_SET);
		fread(&sig_len_bytes, 1, 1, sig_file);
		sig_len = sig_len_bytes;
		if (sig_len >96) {
			printf("FAILED: executable file doesn't have signature or sig length is not correct\n");
			return ERR_BAD_SIG;
		}
		fseek(sig_file, file_size - sig_len - 1, SEEK_SET);	
		fread(sig,1, sig_len, sig_file);
	} else {
		sig_len = fread(sig, 1, sizeof(sig), sig_file);
	}
	
	hexFrom(hex_sig,sig,sig_len);

	printf("Signature: %s\n", hex_sig);
	return ERR_OK;
}

static int sigMain(int argc, char* argv[]){
	err_t code;
	const char* key_name;
	const char* sig_file_name;
	cmd_t cmd;
	// справка
	if (argc < 3)
		return sigUsage();

    cmd = getCommand(argv[1]);

	if (cmd == COMMAND_SIGN || cmd == COMMAND_VFY){
		key_name = findArgument(argc,argv, ARG_KEY);
		if (!key_name){
			printf("%s argument is required\n", ARG_KEY);
			return ERR_CMD_PARAMS; 
		}
		sig_file_name = findArgument(argc, argv, ARG_SIG_FILE);
	
		if (!sig_file_name && !findArgument(argc, argv, ARG_EXEC)){
			printf("One of arguments [%s, %s] is required\n", ARG_SIG_FILE, ARG_EXEC);
			return ERR_CMD_PARAMS;
		}
	}

	switch (cmd)
	{
	case COMMAND_SIGN:
		code = sigSign(argv[argc-1],sig_file_name, key_name);
		break;
	case COMMAND_VFY:
		code = sigVfy(argv[argc-1], sig_file_name, key_name);
		break;
	case COMMAND_PRINT:
		code = sigPrint(argv[argc-1], findArgument(argc, argv, ARG_EXEC) != NULL);
		break;
	default:
		return sigUsage();
	}
	return (code == ERR_OK) ? 0 : -1;
}

err_t sigInit(){
	return cmdReg(_name, _descr, sigMain);
}

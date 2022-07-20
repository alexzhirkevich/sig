#include <stdio.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/btok.h>
#include <bee2/core/err.h>
#include <bee2/core/der.h>
#include <bee2/core/blob.h>
#include <bee2/core/util.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/hex.h>
#include "../cmd.h"

#define SIG_MAX_CERTS 16

#define cmd_t octet

#define ARG_CERT "-cert"
#define ARG_ANCHOR "-anchor"
#define ARG_PASS "-pass"
#define ARG_PRIVKEY "-privkey"
#define ARG_PUBKEY "-pubkey"
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

typedef struct {
    octet sig[96];	                 /* подпись */
    size_t sig_len;	                 /* длина подписи в октетах */
    size_t certs_cnt;				     /* количество сертификатов */
    size_t certs_len[SIG_MAX_CERTS];   /* длины сертификатов */
} cmd_sig_t;

typedef struct
{
	octet cert[1024];
	size_t cert_len;
} cert_data;

typedef struct{
	octet sig[96];
	size_t sig_len;
	bool_t has_cert;
} sig_data;

static int sigUsage(){
	printf(
 		"bee2cmd/%s: %s\n"
 		"Usage:\n"
 		"  %s %s  [%s <certa,certb,...,cert> ] [%s <scheme>] <privkey> <file> <sig>\n"
 		"    sign <file> using <privkey> and write signature to <sig>\n"
		"  options:\n"
		"    %s <certa,certb,...,cert> -- certeficate sequence (optional)\n"
		"    %s <scheme> -- scheme of the private key password\n"
 		"  %s %s [%s <pubkey> | %s <anchor>] <file> <sig>\n"
 		"    verify <file> signature stored in <sig>"
		"  options:\n"
		"    %s <pibkey> -- verification public key\n"
		"    %s <anchor> -- trusted certificate"
 		"  %s %s [%s <cert>] <sig>\n"
 		"    print <sig> to the console\n"
		"  options:\n"
		"    %s <cert> -- file to save certeficate (if signature contains it)\n"
		, 
		_name, _descr,
		_name, ARG_SIGN, ARG_CERT, ARG_PASS,
						 ARG_CERT, ARG_PASS,
		_name, ARG_VFY, ARG_PUBKEY, ARG_ANCHOR,
						ARG_PUBKEY, ARG_ANCHOR,
		_name, ARG_PRINT, ARG_CERT, ARG_CERT
	);
	return -1;
}


/*
*******************************************************************************
Подпись

  SEQ[APPLICATION 78] Signature
    SIZE[APPLICATION 41] -- sig_len
    SIZE[APPLICATION 42] -- cert_cnt
    OCT(APPLICATION 37)(SIZE(96)) -- sig
    OCT[APPLICATION 73](SIZE(sizeof(size_t) * SIG_MAX_CERT)) - cert_len
    SEQ[APPLICATION 75] Cert
      OCT - cert[i]
*******************************************************************************
*/

#define derEncStep(step, ptr, count)\
do {\
	size_t t = step;\
	ASSERT(t != SIZE_MAX);\
	ptr = ptr ? ptr + t : 0;\
	count += t;\
} while(0)\

#define derDecStep(step, ptr, count)\
do {\
	size_t t = step;\
	if (t == SIZE_MAX)\
		return SIZE_MAX;\
	ptr += t, count -= t;\
} while(0)\

static size_t sigEnc(octet buf[], cmd_sig_t* sig, octet* certs[]) {

    der_anchor_t Signature[1];
    der_anchor_t Certs[1];

    size_t count = 0;

    if (!memIsValid(sig, sizeof(cmd_sig_t)))
        return ERR_BAD_SIG;

    for (int i = 0; i < sig->certs_cnt; i++) {
        if (!memIsValid(certs[i], sig->certs_len[i])) {
            return ERR_BAD_CERT;
        }
    }
    derEncStep(derTSEQEncStart(Signature, buf, count, 0x7F4E), buf, count);
    
    derEncStep(derTSIZEEnc(buf, 0x5F29, sig->sig_len), buf, count);
    derEncStep(derTSIZEEnc(buf, 0x5F2A, sig->certs_cnt), buf, count);

    derEncStep(derOCTEnc(buf, sig->certs_len, sizeof(size_t) * SIG_MAX_CERTS), buf, count);

    derEncStep(derTSEQEncStart(Certs, buf, count, 0x7F4B), buf, count);
    for (int i = 0; i < sig->sig_len;i++){
        derOCTEnc(buf, certs[i], sig->certs_len[i]);
    }
    derEncStep(derTSEQEncStop(buf, count, Certs), buf, count);
    derEncStep(derTSEQEncStop(buf, count, Signature), buf,count);

    return count;
}

static size_t sigDec(octet der[], size_t count, cmd_sig_t* sig, octet* certs[]){

    if (!memIsValid(sig, sizeof(cmd_sig_t))){
        return ERR_OUTOFRANGE;
    }

    der_anchor_t Signature[1];
    der_anchor_t CertLen[1];
    der_anchor_t Certs[1];
    octet *ptr = der;

    derDecStep(derTSEQDecStart(Signature, ptr, count, 0x7F4E), ptr, count);

    derDecStep(derTSIZEDec(&sig->sig_len,ptr,count, 0x5F29), ptr, count);
    derDecStep(derTSIZEDec(&sig->certs_cnt,ptr,count, 0x5F2A), ptr, count);

    derDecStep(derOCTDec2((octet *) sig->certs_len, ptr, count, sizeof(size_t) * SIG_MAX_CERTS), ptr, count);

    derDecStep(derTSEQDecStart(CertLen, ptr, count, 0x7F49), ptr, count);
    for (int i = 0; i < sig->sig_len;i++){
        derDecStep(derSIZEDec(&sig->certs_len[i], ptr, count),ptr,count);
    }

    derDecStep(derTSEQDecStart(Certs, ptr, count, 0x7F4B), ptr, count);
    for (int i = 0; i < sig->sig_len;i++){
        if (!memIsValid(certs[i], sig->certs_len[i])){
            return ERR_OUTOFRANGE;
        }
        derDecStep(derOCTDec2(certs[i],ptr, count, sig->certs_len[i]), ptr, count);
    }
    derDecStep(derTSEQDecStop(ptr, Certs), ptr, count);
    derDecStep(derTSEQEncStop(ptr, count, Signature), ptr, count);

    return ptr - der;
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

err_t cvcRead(octet* cvc, size_t* cert_len, const char* cert_file_name){
	err_t code;
	void* state;
	octet* cert;
	char* hex;
	if (!cmdFileValExist(1, &cert_file_name))
		return ERR_FILE_NOT_FOUND;
	if (*cert_len = cmdFileSize(cert_file_name) == SIZE_MAX)
		return ERR_FILE_READ;
	if (*cert_len > 512)
		return ERR_BAD_FORMAT;

	state = blobCreate(*cert_len + sizeof(btok_cvc_t) + 2 * 128 + 1);
	if (!state)
		return ERR_OUTOFMEMORY;
	cert = (octet*)state;
	ASSERT(memIsValid(cvc, *cert_len));
		
	FILE* fp;
	code = (fp = fopen(cert_file_name, "rb")) ? ERR_OK : ERR_FILE_OPEN;
	ERR_CALL_HANDLE(code, blobClose(state));
	*cert_len = fread(cert, 1, *cert_len, fp);
	fclose(fp);
	ERR_CALL_HANDLE(code, blobClose(state));

	ERR_CALL_HANDLE(code, blobClose(state));
	blobClose(state);
	
	return ERR_OK;
}

// err_t cvcWrite(btok_cvc_t* cvc, const char* cert_file_name, octet* privkey, size_t privkey_len){
// 	err_t code;
// 	size_t cert_len;
// 	octet cert[512 + sizeof(btok_cvc_t) + 257];
// 	FILE* fp;

// 	ASSERT(memIsValid(cvc, sizeof(btok_cvc_t)));
	
// 	btokCVCWrap(cert, &cert_len, cvc, privkey, privkey_len);
// 	ERR_CALL_CHECK(code);

// 	if (!cert_file_name){
// 		return ERR_FILE_CREATE;
// 	}

// 	code = (fp = fopen(cert_file_name, "wb")) ? ERR_OK : ERR_FILE_CREATE;
// 	ERR_CALL_CHECK(code);
	
// 	fwrite(cert, 1, cert_len, fp);
// 	fclose(fp);
// 	ERR_CALL_CHECK(code);

// 	return ERR_OK;
// }

static err_t sigSign(
	const char* file_name, 
	const char* sig_file_name, 
	const char* pass_sheme, 
	const char* pk_container_name,
	const char* cert_file_name
	){
	octet key[64];
	octet hash[64];
	// octet sig[96];
	// size_t sig_len;
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
	bool_t is_embedded;
	cmd_pwd_t pwd = 0;
	btok_cvc_t cvc;
	sig_data s_data;
	cert_data c_data;
	const char* file_with_sig_name;
	const char* open_mode;

	is_embedded = sig_file_name == NULL;
	file_with_sig_name = is_embedded ? sig_file_name : file_name;
	open_mode = is_embedded ? "wb" : "a";

	if (!pass_sheme){
		return ERR_KEY_NOT_FOUND;
	}

	error = cmdPwdRead(pwd,pass_sheme);
	ASSERT(cmdPwdIsValid(pwd));
	ERR_CALL_HANDLE(error, cmdPwdClose(pwd));

	if (!pk_container_name){
		return ERR_KEY_NOT_FOUND;
	}
	error = cmdPrivkeyRead(key, &key_size, pk_container_name, pwd);
	ERR_CALL_HANDLE(error, cmdPwdClose(pwd));

	s_data.has_cert = cert_file_name != NULL;
	if (s_data.has_cert){
		error = cvcRead(c_data.cert, &c_data.cert_len, cert_file_name);
		ERR_CALL_HANDLE(error, cmdPwdClose(pwd));
	}

	s_data.sig_len = key_size*3/2;

	fclose(key_file);

    memSetZero(hash,sizeof(hash));

	if (!file_name){
		return ERR_FILE_NOT_FOUND;
	}

	if (bsumHashFileWithEndPadding(hash, key_size == 32 ? 0 : key_size*8, file_name, 0) != 0){
		printf("FAILED: an error occured while hashing the file\n");
		return ERR_BAD_HASH;
	}	
	
	curve = sigCurveName(key_size*4);
	if (!curve){
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

    memSetZero(s_data.sig, sizeof(s_data.sig));

	if (rngIsValid())
		rngStepR(t, t_len = key_size, 0);
	else
		t_len = 0;

	error = bignSign2(s_data.sig, &params, oid_der, oid_len,hash, key, t, t_len);
	ERR_CALL_CHECK(error);

	sig_file = fopen(file_with_sig_name, open_mode);
	if (!sig_file) {
		printf("%s: FAILED [open]\n", sig_file_name);
		return ERR_FILE_OPEN;
	}

	// if (cert_file_name){

	// 	size_t cert_len;
	// 	octet cert[512 + sizeof(btok_cvc_t) + 257];
		
	// 	memCopy(cvc.sig, sig, sizeof(sig));
	// 	cvc.sig_len = sig_len;
		
	// 	error = btokCVCWrap(cert, &cert_len, &cvc, key, key_size);
	// 	ERR_CALL_CHECK(error);
		
	// 	memCopy(s_data.cert, cert,cert_len);
	// 	s_data.cert_len = cert_len;
	
	// } else {

	if (s_data.has_cert){
		fwrite(&c_data, sizeof(cert_data), 1, sig_file);
	}
	fwrite(&s_data, sizeof(sig_data), 1, sig_file);
	// }
	fclose(sig_file);

    printf("SUCCESS: %s saved to %s\n", cert_file_name ? "certificate with signature" : "signature", file_with_sig_name);

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
	bool_t is_embedded;
	const char* file_with_sig_name;

	is_embedded = sig_file_name != NULL;
	file_with_sig_name = is_embedded ? sig_file_name : file_name;

	if (!key_name){
		return ERR_KEY_NOT_FOUND;
	}

	key_file = fopen(key_name, "rb");

	if (!key_file){
		printf("%s: FAILED [open]\n", key_name);
		return ERR_FILE_OPEN;
	}

	key_size = fread(key,1, sizeof(key), key_file);
	sig_size = key_size*3/4;

	if (is_embedded){
		end_padding = 0;
	} else {
		end_padding = sig_size+1;
	}

	if (!file_name){
		return ERR_FILE_NOT_FOUND;
	}

	if (bsumHashFileWithEndPadding(hash, key_size == 64 ? 0 : key_size*4, file_name, end_padding) != 0){
		printf("FAILED: an error occured while hashing the file\n");
		return ERR_BAD_HASH;
	}

	curve = sigCurveName(key_size*2);
	if (!curve){
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

	sig_file = fopen(file_with_sig_name, "rb");
	if (!sig_file){
		printf("%s: FAILED [open]\n", file_with_sig_name);
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

	if (!sig_file_name){
		return ERR_FILE_NOT_FOUND;
	}

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
		key_name = findArgument(argc,argv, ARG_PASS);
		if (!key_name){
			printf("%s argument is required\n", ARG_PASS);
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
		code = sigSign(argv[argc-1],sig_file_name, key_name, 0,0);
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

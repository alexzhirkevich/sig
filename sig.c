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
#include "bee2/core/prng.h"
#include "bee2/core/str.h"

#define SIG_MAX_CERTS 16
#define CERTS_DELIM ','


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

#define COMMAND_UNKNOWN 0
#define COMMAND_VFY 1
#define COMMAND_SIGN 2
#define COMMAND_PRINT 3

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

extern err_t cmdCVCRead(octet cert[], size_t* cert_len, const char* file);

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


#pragma region Справка по использованию

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

#pragma endregion


#pragma region Кодирование подписи

/*
*******************************************************************************
Кодирование подписи

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
        return SIZE_MAX;

    for (size_t i = 0; i < sig->certs_cnt; i++) {
        if (!memIsValid(certs[i], sig->certs_len[i])) {
            return SIZE_MAX;
        }
    }

    derEncStep(derTSEQEncStart(Signature, buf, count, 0x7F4E), buf, count);
    
    derEncStep(derTSIZEEnc(buf, 0x5F29, sig->sig_len), buf, count);
    derEncStep(derOCTEnc(buf, sig->sig,sig->sig_len), buf, count);

    derEncStep(derTSIZEEnc(buf, 0x5F2A, sig->certs_cnt), buf, count);

    derEncStep(derOCTEnc(buf, sig->certs_len, sizeof(size_t) * SIG_MAX_CERTS), buf, count);

    derEncStep(derTSEQEncStart(Certs, buf, count, 0x7F4B), buf, count);
    for (size_t i = 0; i < sig->certs_cnt;i++){
        derEncStep(derOCTEnc(buf, certs[i], sig->certs_len[i]), buf, count);
    }
    derEncStep(derTSEQEncStop(buf, count, Certs), buf, count);
    derEncStep(derTSEQEncStop(buf, count, Signature), buf,count);

    ASSERT(derIsValid(buf,count));

    return count;
}

static size_t sigDec(octet der[], size_t count, cmd_sig_t* sig, octet* certs[]){

    der_anchor_t Signature[1];
    der_anchor_t Certs[1];
    octet *ptr = der;

    if (!derIsValid(der, count)){
        return SIZE_MAX;
    }

    if (!memIsNullOrValid(sig, sizeof(cmd_sig_t))){
        return SIZE_MAX;
    }

    derDecStep(derTSEQDecStart(Signature, ptr, count, 0x7F4E), ptr, count);

    derDecStep(derTSIZEDec(&sig->sig_len,ptr,count, 0x5F29), ptr, count);
    derDecStep(derOCTDec2(sig->sig, ptr, count ,sig->sig_len), ptr, count);

    derDecStep(derTSIZEDec(&sig->certs_cnt,ptr,count, 0x5F2A), ptr, count);

    derDecStep(derOCTDec2((octet*)sig->certs_len, ptr, count, sizeof(size_t) * SIG_MAX_CERTS), ptr, count);

    derDecStep(derTSEQDecStart(Certs, ptr, count, 0x7F4B), ptr, count);
    for (size_t i = 0; i < sig->certs_cnt;i++){
        if (!memIsValid(certs[i], sig->certs_len[i])){
            return SIZE_MAX;
        }
        derDecStep(derOCTDec2(certs[i],ptr, count, sig->certs_len[i]), ptr, count);
    }
    derDecStep(derTSEQDecStop(ptr, Certs), ptr, count);
    derDecStep(derTSEQDecStop(ptr, Signature), ptr, count);

    return ptr - der;
}

#pragma endregion


#pragma region Читение/запись подписи


/*
*******************************************************************************
 Чтение подписи из файла
*******************************************************************************
*/

err_t cmdSigRead(cmd_sig_t* sig, octet** certs, char* file){

    ASSERT(memIsNullOrValid(sig, sizeof (cmd_sig_t)));

    FILE* fp;
    size_t der_count;
    char *files[] = { file };
    octet * buf = 0;

    ERR_CALL_CHECK(cmdFileValExist(1, files));
    fp = fopen(file, "rb");


    fseek(fp, - (signed)sizeof (size_t), SEEK_END);
    fread(&der_count, sizeof(size_t), 1, fp);

    buf = (octet*) blobCreate(der_count);

    if (!buf){
        return ERR_OUTOFMEMORY;
    }

    fseek(fp, - (signed)(der_count - sizeof(size_t)), SEEK_CUR);

    if (!derIsValid(buf, der_count)) {
        blobClose(buf);
        return ERR_BAD_SIG;
    }

    if (sigDec(buf, der_count, sig, certs) == SIZE_MAX){
        return ERR_BAD_SIG;
    }

    return ERR_OK;
}

/*
*******************************************************************************
 Запись подписи в файл

 Подпись читается с конца, поэтому может быть дописана в непустой файл
 (при указании append = TRUE)
*******************************************************************************
*/
err_t cmdSigWrite(cmd_sig_t* sig, octet** certs, const char* file, bool_t append){

    size_t count;
    octet der[SIG_MAX_CERTS * (512 + 128) + 96 + 16];
    FILE* fp;

    count = sigEnc(der, sig, certs);
    fp = fopen(file, append ? "a" : "wb");

    if (!fp){
        return ERR_FILE_OPEN;
    }

    if (fwrite(der, 1, count, fp) != count){
        return ERR_OUTOFMEMORY;
    }
    fwrite(&count, sizeof(size_t), 1, fp);
    fclose(fp);

    return ERR_OK;
}

#pragma endregion



#pragma region Разбор опций командной строки

static char getCommand(const char* arg) {
    if (!arg){
        return COMMAND_UNKNOWN;
    }

    const char* args[]      = {ARG_VFY,       ARG_SIGN,       ARG_PRINT };
    const char commands[]  = {COMMAND_VFY, COMMAND_SIGN, COMMAND_PRINT};
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

/*
*******************************************************************************
 Разбор опций командной строки

 Опции возвращаются по адресам
 privkey [privkey_len],
 pubkey [pubkey_len],
 anchor_cert [anchor_cert_len],
 file, sig_file,
 sig
 certs [certs_count]
 certs_lens [certs_count]
 Любой из адресов может бытьнулевым, и тогда соответствующая опция не возвращается.
 Более того, ее указаниев командной строке считается ошибкой.

 В случае успеха по адресу readc возвращается число обработанных аргументов.
*******************************************************************************
*/

static err_t sigParseOptions(
        int argc,
        char** argv,
        octet* privkey,
        size_t * privkey_len,
        octet* pubkey,
        size_t * pubkey_len,
        octet* anchor_cert,
        size_t* anchor_cert_len,
        char* file,
        char* sig_file,
        cmd_sig_t * sig,
        octet** certs,
        size_t* certs_lens,
        size_t* certs_count
        ){

    cmd_pwd_t pwd;
    bool_t pwd_provided = FALSE;

    char cmd = getCommand(argv[0]);
    if (cmd == COMMAND_UNKNOWN)
        return ERR_CMD_PARAMS;

    if (cmd == COMMAND_VFY &&
        !findArgument(argc, argv, ARG_PUBKEY) &&
        !findArgument(argc, argv, ARG_ANCHOR)){
        return ERR_BAD_INPUT;
    }

    while (argc >0 && strStartsWith(*argv, "-")){

        if (argc < 2){
            return ERR_CMD_PARAMS;
        }

        // прочитать схему личного ключа
        if (strEq(*argv, ARG_PASS)){
            cmdPwdRead(&pwd, argv[1]);
            pwd_provided = TRUE;
        }

        // прочитать доверенный сертификат
        if (strEq(*argv, ARG_ANCHOR)) {
            if (!anchor_cert){
                return ERR_CMD_PARAMS;
            }
            ASSERT(memIsValid(anchor_cert_len, sizeof(size_t)));

            cmdCVCRead(anchor_cert, anchor_cert_len, argv[1]);
        }

        // прочитать открытый ключ
        if (strEq(*argv, ARG_PUBKEY)){
            if (!pubkey){
                return ERR_CMD_PARAMS;
            }
            ASSERT(memIsValid(pubkey_len, sizeof(size_t)));

            FILE* fp = fopen(argv[1], "rb");
            if (!fp){
                printf("ERROR: failed to open public key file '%s'", argv[1]);
                return ERR_FILE_OPEN;
            }
            *pubkey_len = fread(pubkey, 1, 128, fp);
            fclose(fp);
        }


        // прочитать сертификаты
        if (strEq(*argv, ARG_CERT)) {
            if (!certs) {
                return ERR_CMD_PARAMS;
            }
            ASSERT(memIsValid(certs_count, sizeof(size_t)));

            char* m_certs = argv[1];

            *certs_count = 0;
            bool_t stop = FALSE;
            while (!stop){
                size_t i = 0;
                for (; m_certs[i] != '\0' && m_certs[i] != CERTS_DELIM; i++);
                if (m_certs[i] == '\0')
                    stop = TRUE;
                else
                    m_certs[i] = '\0';
                cmdCVCRead(certs[*certs_count], certs_lens + *certs_count, m_certs);
                m_certs += i+1;
                *certs_count++;
            }
        }

        argc -= 2;
        argv += 2;
    }

    switch (cmd) {
        case COMMAND_SIGN:
            if (argc != 3) {
                return ERR_CMD_PARAMS;
            }

            //прочитать личный ключ
            if (privkey == NULL){
                return ERR_CMD_PARAMS;
            }
            ASSERT(memIsValid(privkey_len, sizeof (size_t)));

            //если схема пароля не предоставлена, личный ключ читается как открытый
            if (pwd_provided){
                cmdPrivkeyRead(privkey, privkey_len, argv[0], pwd);
            } else {
                FILE *fp = fopen(argv[0],"rb");
                if (!fp){
                    printf("ERROR: failed to open public key file '%s'", argv[0]);
                    return ERR_FILE_OPEN;
                }
                *privkey_len = fread(privkey, 1, 64, fp);
                fclose(fp);
            }

            //прочитать имя подписываемого файла
            ASSERT(memIsValid(file, strlen(argv[1])));
            memCopy(file, argv[1], strLen(argv[1]));

            //прочитать имя файла c подписью
            ASSERT(memIsValid(sig_file, strlen(argv[20])));
            memCopy(sig_file, argv[2], strLen(argv[2]));

            break;
        case COMMAND_VFY:
            if (argc != 2){
                return ERR_CMD_PARAMS;
            }

            //прочитать имя подписанного файла
            ASSERT(memIsValid(file, strlen(argv[0])));
            memCopy(file, argv[0], strLen(argv[0]));

            //прочитать имя файла c подписью
            ASSERT(memIsValid(sig_file, strlen(argv[1])));
            memCopy(sig_file, argv[1], strLen(argv[1]));

            // прочитать подпись
            if (sig && certs) {
                ERR_CALL_CHECK(cmdSigRead(sig, certs, sig_file));
            }

        case COMMAND_PRINT:
            if (argc != 1){
                return ERR_CMD_PARAMS;
            }

            if (!sig_file){
                return ERR_CMD_PARAMS;
            }

            // прочитать имя файла c подписью
            ASSERT(memIsValid(sig_file, strlen(argv[0])));
            memCopy(sig_file, argv[0], strLen(argv[0]));

            // прочитать подпись
            if (sig && certs){
                ERR_CALL_CHECK(cmdSigRead(sig, certs, sig_file));
            }
        default:
            break;
    }

    return ERR_OK;
}

#pragma  endregion



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




static err_t sigSign(int argc, char* argv[]){

    char* file_name;
    char* sig_file_name;

}

static err_t sigSign2(
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
		error = cmdCVCRead(c_data.cert, &c_data.cert_len, cert_file_name);
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


static err_t sigSelfTest(){
    octet cert1[1024];
    octet cert1_dec[1024];
    octet cert2[1024];
    octet cert2_dec[1024];

    size_t der_len;
    octet der[4096];

    cmd_sig_t cmd_sig[1];
    cmd_sig_t cmd_sig_dec[1];

    octet state[1024];
    bign_params params[1];
    octet privkey[32];
    octet pubkey[64];
    octet hash[32];
    const octet oid[] = {
            0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
    };
    octet sig[48];
    // bign-genkeypair
    hexTo(privkey,
          "1F66B5B84B7339674533F0329C74F218"
          "34281FED0732429E0C79235FC273E269");
    ASSERT(sizeof(state) >= prngEcho_keep());
    prngEchoStart(state, privkey, 32);
    if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
        bignGenKeypair(privkey, pubkey, params, prngEchoStepR,
                       state) != ERR_OK ||
        !hexEq(pubkey,
               "BD1A5650179D79E03FCEE49D4C2BD5DD"
               "F54CE46D0CF11E4FF87BF7A890857FD0"
               "7AC6A60361E8C8173491686D461B2826"
               "190C2EDA5909054A9AB84D2AB9D99A90"))
        return ERR_SELFTEST;
    // bign-valpubkey
    if (bignValPubkey(params, pubkey) != ERR_OK)
        return ERR_SELFTEST;
    // bign-sign
    if (beltHash(hash, beltH(), 13) != ERR_OK)
        return ERR_SELFTEST;
    if (bignSign2(sig, params, oid, sizeof(oid), hash, privkey,
                  0, 0) != ERR_OK)
        return ERR_SELFTEST;
    if (!hexEq(sig,
               "19D32B7E01E25BAE4A70EB6BCA42602C"
               "CA6A13944451BCC5D4C54CFD8737619C"
               "328B8A58FB9C68FD17D569F7D06495FB"))
        return ERR_SELFTEST;
    if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) != ERR_OK)
        return ERR_SELFTEST;
    sig[0] ^= 1;
    if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) == ERR_OK)
        return ERR_SELFTEST;

    memSetZero(cmd_sig->sig, 96);
    memSetZero(cmd_sig_dec->sig, 96);
    for (int i = 0; i< SIG_MAX_CERTS; i++){
        cmd_sig->certs_len[i] = 0;
        cmd_sig_dec->certs_len[i] = 0;
    }

    if(cmdCVCRead(cert1, &cmd_sig->certs_len[0],"cert0") != ERR_OK)
        return ERR_SELFTEST;
    if(cmdCVCRead(cert2, &cmd_sig->certs_len[1],"cert1") != ERR_OK)
        return ERR_SELFTEST;

    memCopy(cmd_sig->sig,sig,sizeof (sig));
    cmd_sig->sig_len = sizeof (sig);
    cmd_sig->certs_cnt = 2;

    octet *certs[]= {cert1, cert2};
    octet *certs_dec[]= {cert1_dec, cert2_dec};

    der_len = sigEnc(der, cmd_sig, certs);

    if (der_len == SIZE_MAX)
        return ERR_SELFTEST;

    if (sigDec(der, der_len, cmd_sig_dec, certs_dec) == SIZE_MAX)
        return ERR_SELFTEST;


    ASSERT(memEq(cmd_sig->sig, cmd_sig_dec->sig, sizeof (sig)));
    ASSERT(cmd_sig->sig_len ==cmd_sig_dec->sig_len);
    ASSERT(cmd_sig->certs_cnt ==cmd_sig_dec->certs_cnt);
    ASSERT(memEq(cert1, cert1_dec, cmd_sig->certs_len[0]));
    ASSERT(memEq(cert2, cert2_dec, cmd_sig->certs_len[1]));

    return ERR_OK;
}


static int sigMain(int argc, char* argv[]){

    printf(errMsg(sigSelfTest()));
    return 0;

    err_t code;
    const char* key_name;
    const char* sig_file_name;
    cmd_sig_command cmd;
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
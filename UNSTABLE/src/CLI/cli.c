#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>

#include "../../include/CSON/cson.h"
#include "../../include/AES-256-GCM/AES.h"
#include "../../include/common/bt_utils.h"
#include "../../include/common/bt_printf.h"
#include "../../include/common/bt_api.h"
#include "../../include/common/bt_log.h"

// Chemin réel de error.log (voir bt_log.c) : %APPDATA% sous Windows, $HOME sous Linux.
// Ce texte passe dans print_ERR (format printf) : le % de %APPDATA% doit être doublé.
#ifdef _WIN32
    #define ERR_SYSTEM_MSG "Error system, reason is inside '%%APPDATA%%\\CShield\\UNSTABLE\\log\\error.log'"
#else
    #define ERR_SYSTEM_MSG "Error system, reason is inside '~/CShield/UNSTABLE/log/error.log'"
#endif

typedef enum {
    crt,
    dlt,
    mdf,
    shw,
    gen,
    mng,
    inf
} methode;

static int fillUpEntryFromARGV(CShieldParams* e,char* argv[],int argc,methode m);
int AES_GCM_Decrypt_returnCodeHandler(int code);
int AES_GCM_Encrypt_returnCodeHandler(int code);
static int isTagAlreadyHere(char** tags,size_t numberOfTags,char* newTag);
static int witchBox(CShieldParams p);

int main(int argc, char *argv[]) {
    initConsole();
    #ifdef _WIN32
            if(convertARGV(argv,argc)){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }
    #endif
    int state = 0;
    if(argc == 1){
        // Faire le CLI custom
        return 0;
    }
    // Nom du vault en UTF-8, pour l'affichage seulement : argv[2] reste tel quel pour ouvrir le fichier
    char* displayName = NULL;
    if(argc > 2){
        #ifdef _WIN32
            if(bt_cp1252ToUtf8(&displayName,argv[2])){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }
        #else
            displayName = argv[2];
        #endif
    }
    methode m;

    if(isOneOfThemEqual(argv[1],2,"create","crt")){
        m = crt;
    }else if(isOneOfThemEqual(argv[1],2,"delete","dlt")){
        m = dlt;
    }else if(isOneOfThemEqual(argv[1],2,"modify","mdf")){
        m = mdf;
    }else if(isOneOfThemEqual(argv[1],2,"show","shw")){
        m = shw;
    }else if(isOneOfThemEqual(argv[1],2,"generate","gen")){
        m = gen;
    }else if(isOneOfThemEqual(argv[1],3,"--info","-i","-I") ||
             isOneOfThemEqual(argv[1],3,"--help","-h","-H") ||
             isOneOfThemEqual(argv[1],3,"--version","-v","-V")){
        m = inf;
    }else if(isOneOfThemEqual(argv[1],3,"init","vaults","password")){
        m = mng;
    }else{
        print_WRN("Methode '%s' non-existant...",argv[1]);
        printf("\n");
        print_INF("You can check command with 'cshild --help'");
        return 1;
    }

    switch (m){
    case crt:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",displayName);
            return 1;
        }

        CShieldParams e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }

        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            if(state == AES_ERR_MDP){
                bt_logAction('@',displayName,1);
            }
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        if(e.newPassword == 1){
            printf("Enter the new password : ");
            state = bt_fgetss(&e.pwd);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }

            char* buffer = NULL;
            printf("Enter the new password again: ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
            if(bt_strcmp(e.pwd,buffer) != 0){
                print_WRN("The two password are not the same");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                nukeString(buffer,bt_strlen(buffer));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                free(buffer);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
            nukeString(buffer,bt_strlen(buffer));
            free(buffer);
        }else{
            print_WRN("No password provided through '--password' flags. Generate one ?");
            printf("Accept ? : ");printf("[");char_RGB(0,255,0,'Y');printf("/");char_RGB(255,0,0,'n');printf("] : ");
            state = getValidation();
            if(state == 1){
                GenParameter p;
                state = getGenParam(&p);
                if(state == 1){
                    print_ERR(ERR_SYSTEM_MSG);
                    uint8_tToZero(b_encryptedVault,size_encryptedVault);
                    uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                    nukeString(vaultPWD,bt_strlen(vaultPWD));
                    free(b_encryptedVault);
                    free(b_decryptedVault);
                    free(vaultPWD);
                    free(vaultPath);
                    bt_deepFree(e.nbOfTags,(void**)e.tags);
                    return 1;
                }
                state = bt_pwdGen(&e.pwd,p);
                if(state == 1){
                    print_ERR(ERR_SYSTEM_MSG);
                    uint8_tToZero(b_encryptedVault,size_encryptedVault);
                    uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                    nukeString(vaultPWD,bt_strlen(vaultPWD));
                    free(b_encryptedVault);
                    free(b_decryptedVault);
                    free(vaultPWD);
                    free(vaultPath);
                    bt_deepFree(e.nbOfTags,(void**)e.tags);
                    return 1;
                }
            }else if(state == 2){
                print_WRN("Not a valid respond, action canceled (Must respond with 'Y' or 'N')");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        state = addEntry(&vaultRoot,e);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_WRN("Password empty");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 3){
            print_WRN("Entry already existing");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
        free(b_decryptedVault);
        b_decryptedVault = (uint8_t*)jsonTmp;
        size_decryptedVault = bt_strlen(jsonTmp);

        free(b_encryptedVault);
        b_encryptedVault = NULL;
        state = AES_GCM_Encrypt(&b_encryptedVault,&size_encryptedVault,b_decryptedVault,size_decryptedVault,vaultPWD);
        if(AES_GCM_Encrypt_returnCodeHandler(state)){
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        print_SUC("New entry successfully saved");
        bt_logAction('+',displayName,1);

        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));
        nukeString(e.pwd,bt_strlen(e.pwd));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        free(e.pwd);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);

        break;
    }
    case dlt:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",displayName);
            return 1;
        }

        CShieldParams e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }
        if(e.id == NULL){
            print_WRN("ID not provided, will proceed to remove ALL entries from '%s'",e.app);
            printf("Continue ? : ");printf("[");char_RGB(0,255,0,'Y');printf("/");char_RGB(255,0,0,'n');printf("] : ");
            state = getValidation();

            if(state == 0){
                print_INF("Action canceled");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state == 2){
                print_WRN("Not a valid respond, Action canceled (Must respond with 'Y' or 'N')");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
        }

        // 1. On récupére le path du vault et le mdp
        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 2. On récupére le vault en mémoire
        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 3. On décrypte le vault en mémoire
        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            if(state == AES_ERR_MDP){
                bt_logAction('@',displayName,1);
            }
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 4. On extract son JSON avec CSON pour le manipuler
        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        // 5. On applique l'api
        int numberOfRemovedEntry;
        state = removeEntry(&vaultRoot,e,&numberOfRemovedEntry);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_WRN("No application named '%s' inside '%s'",e.app,displayName);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 3){
            print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,displayName);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 4){
            print_INF("No more ID inside application name '%s', app removed",e.app);
        }

        // 6. On réecrit le Json de CSON en char en mémoire
        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
        free(b_decryptedVault);
        b_decryptedVault = (uint8_t*)jsonTmp;
        size_decryptedVault = bt_strlen(jsonTmp);

        // 7. On ré-encrypte
        free(b_encryptedVault);
        b_encryptedVault = NULL;
        state = AES_GCM_Encrypt(&b_encryptedVault,&size_encryptedVault,b_decryptedVault,size_decryptedVault,vaultPWD);
        if(AES_GCM_Encrypt_returnCodeHandler(state)){
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 8. On le replace dans l'ancien path
        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 9. On informe l'utilisateur
        print_SUC("%d entry successfully removed",numberOfRemovedEntry);
        bt_logAction('-',displayName,numberOfRemovedEntry);

        // 10. On clean tout en mémoire
        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);

        break;
    }
    case mdf:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",displayName);
            return 1;
        }

        CShieldParams e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }if(e.tagsMethode == 1){
            print_WRN("New tag(s) provided through '--tags', old tag(s) will be overwrite");
            printf("Continue ? : ");printf("[");char_RGB(0,255,0,'Y');printf("/");char_RGB(255,0,0,'n');printf("] : ");
            state = getValidation();

            if(state == 0){
                print_INF("If you want to add or remove tags you can use flags '--add-tags' or '--remove-tags'");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state == 2){
                print_WRN("Not a valid respond, Action canceled (Must respond with 'Y' or 'N')");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
        }

        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            if(state == AES_ERR_MDP){
                bt_logAction('@',displayName,1);
            }
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        if(e.newPassword == 1){
            printf("Enter the new password : ");
            state = bt_fgetss(&e.pwd);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }

            char* buffer = NULL;
            printf("Enter the new password again: ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
            if(bt_strcmp(e.pwd,buffer) != 0){
                print_WRN("The two password are not the same");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                nukeString(buffer,bt_strlen(buffer));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                free(buffer);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
            nukeString(buffer, bt_strlen(buffer)); free(buffer);
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        size_t badtag = (size_t)-1;
        state = modEntry(&vaultRoot,e,&badtag);
        if(state != 0){
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
            }else if(state == 2){
                print_WRN("No application named '%s' inside '%s'",e.app,displayName);
            }else if(state == 3){
                print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,displayName);
            }else if(state == 4){
                print_WRN("Application name '%s' already inside '%s'",e.newAppName,displayName);
            }else if(state == 5){
                print_WRN("ID name '%s' already inside '%s'",e.newIDName,e.app);
            }else if(state == 6){
                print_WRN("New password for the app '%s' in ID '%s' is empty",e.app,e.id);
            }else if(state == 7){
                print_WRN("Tag '%s' already inside the application '%s' in ID '%s'",e.tags[badtag],e.app,e.id);
            }else if(state == 8){
                print_WRN("Tag '%s' is not inside the application '%s' in ID '%s'",e.tags[badtag],e.app,e.id);
            }
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
        free(b_decryptedVault);
        b_decryptedVault = (uint8_t*)jsonTmp;
        size_decryptedVault = bt_strlen(jsonTmp);

        free(b_encryptedVault);
        b_encryptedVault = NULL;
        state = AES_GCM_Encrypt(&b_encryptedVault,&size_encryptedVault,b_decryptedVault,size_decryptedVault,vaultPWD);
        if(AES_GCM_Encrypt_returnCodeHandler(state)){
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        print_SUC("Modification successfully saved");
        bt_logAction('*',displayName,1);

        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));
        nukeString(e.pwd,bt_strlen(e.pwd));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        free(e.pwd);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);

        break;
    }
    case shw:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",displayName);
            return 1;
        }

        CShieldParams e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }
        int box = witchBox(e);
        if(box == 0){
            print_WRN("Nothing to show: use '--app', '--app' with '--id', '--tags' or '--search'");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }

        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }

        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            if(state == AES_ERR_MDP){
                bt_logAction('@',displayName,1);
            }
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
            return 1;
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        if(box == 1){
            CShieldEntry entry;
            state = getSingleEntry(&vaultRoot,&entry,e);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }else if(state == 2){
                print_WRN("No application named '%s' inside '%s'",e.app,displayName);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }else if(state == 3){
                print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,displayName);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }

            bt_boxSingleEntry(&entry,e.show);
            bt_freeCShieldEntry(&entry);
        }else if(box == 2){
            CShieldEntry* entries;
            size_t numberOfEntries;
            state = getAllFromApp(&vaultRoot,&entries,&numberOfEntries,e);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }else if(state == 2){
                print_WRN("No application named '%s' inside '%s'",e.app,displayName);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }

            bt_boxMultiEntry(entries,numberOfEntries,e.show);
            for(size_t i=0;i<numberOfEntries;i++){
                bt_freeCShieldEntry(&entries[i]);
            }
            free(entries);
        }else if(box == 3){
            CShieldEntry* entries;
            size_t numberOfEntries;
            state = getMatchingTags(&vaultRoot,&entries,&numberOfEntries,e);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }

            bt_boxTagsMatching(entries,numberOfEntries,e.show,e.tags,e.nbOfTags,e.OpeLogTAGS);
            for(size_t i=0;i<numberOfEntries;i++){
                bt_freeCShieldEntry(&entries[i]);
            }
            free(entries);
        }else if(box == 4){
            CShieldEntry* entries;
            size_t numberOfEntries;
            state = getMatchingWord(&vaultRoot,&entries,&numberOfEntries,e);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }

            bt_boxWordMatching(entries,numberOfEntries,e.show,e.searchedWords,e.nbOfSearchedWord,e.OpeLogWORD);
            for(size_t i=0;i<numberOfEntries;i++){
                bt_freeCShieldEntry(&entries[i]);
            }
            free(entries);
        }else if(box == 6){
            CShieldAppInfo* apps = NULL;
            size_t numberOfApp = 0;
            state = getCShieldAllAppsInfo(&vaultRoot,&apps,&numberOfApp);
            if(state){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }

            state = bt_boxApps(apps,numberOfApp);
            for(size_t i=0;i<numberOfApp;i++){
                bt_freeCShieldAppInfo(&(apps)[i]);
            }
            free(apps);
            if(state){
                print_ERR("Something when wrong while printing bt_boxApps");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }
        }else if(box == 7){
            CShieldEntry entry;
            state = getCShieldPasswordHistory(&vaultRoot,&entry,e);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }else if(state == 2){
                print_WRN("No application named '%s' inside '%s'",e.app,displayName);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }else if(state == 3){
                print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,displayName);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                freeValue(vaultRoot);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);
                return 1;
            }

            bt_boxPwdHistory(&entry,e.show);
            bt_freeCShieldEntry(&entry);
        }

        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);
        bt_deepFree(e.nbOfSearchedWord,(void**)e.searchedWords);

        break;
    }
    case gen:{
        CShieldParams e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }

        char* generatedString = NULL;
        state = bt_pwdGen(&generatedString,e.genParam);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }

        print_SUC("Password generated");

        printf("\n  Length  %d\n",e.genParam.lenght);
        printf("  A-Z ");if(e.genParam.uppercase){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}
        printf("   a-z ");if(e.genParam.lowercase){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}
        printf("   0-9 ");if(e.genParam.digits){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}
        printf("   sym ");if(e.genParam.symbols){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}
        printf("\n\n");

        printf("  %s\n\n",generatedString);

        break;
    }
    case mng:{
        if(bt_strcmp(argv[1],"init") == 0){
            if(argc > 3 ){
                print_WRN("Too many parameters (%d)",argc);
                return 1;
            }else if(argc < 3){
                print_WRN("Not enough parameters (%d)",argc);
                return 1;
            }

            // Le chemin est récupéré AVANT la création : s'il échoue, aucun fichier n'est créé
            char* pathNewVault = NULL;
            state = getVaultPathFromName(&pathNewVault,argv[2]);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }

            state = initNewBlankVault(argv[2]);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                free(pathNewVault);
                return 1;
            }else if(state == 2){
                print_WRN("Invalid name: empty, start with '.' or contain path char / forbidden under Windows");
                free(pathNewVault);
                return 1;
            }else if(state == 3){
                print_WRN("Vault '%s' already exists",displayName);
                free(pathNewVault);
                return 1;
            }

            char* vaultPWD = NULL;
            char* buffer = NULL;
            print_INF("Remember or write down your master key, if you lost it NO RECOVERY POSSIBLE");
            printf("Enter the password of the vault : ");
            state = bt_fgetss(&vaultPWD);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                remove(pathNewVault);
                free(pathNewVault);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                remove(pathNewVault);
                free(pathNewVault);
                return 1;
            }
            printf("Enter the password of the vault again : ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(pathNewVault);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(pathNewVault);
                return 1;
            }

            if(bt_strcmp(vaultPWD,buffer) != 0){
                print_WRN("The two password are not the same");
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(buffer,bt_strlen(buffer));
                free(vaultPWD);
                free(buffer);
                free(pathNewVault);
                return 1;
            }
            nukeString(buffer,bt_strlen(buffer));
            free(buffer);

            state = AES_GCM_Encrypt_File(pathNewVault,vaultPWD);
            if(AES_GCM_Encrypt_returnCodeHandler(state)){
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(pathNewVault);
                return 1;
            }

            print_SUC("New vault '%s' successfully created",displayName);
            bt_logAction('v',displayName,0);

            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(pathNewVault);

        }else if(bt_strcmp(argv[1],"vaults") == 0){
            if(argc > 2 ){
                print_WRN("Too many parameters (%d)",argc);
                return 1;
            }else if(argc < 2){
                print_WRN("Not enough parameters (%d)",argc);
                return 1;
            }
            char** listeOfVaultName = NULL;
            size_t* listeOfVaultSize = NULL;
            size_t numberOfVault;
            state = getAllVaultNameAndSize(&listeOfVaultName,&listeOfVaultSize,&numberOfVault);
            if(state){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }
            #ifdef _WIN32
                // Les noms lus sur le disque sont en Windows-1252 : conversion pour l'affichage
                for(size_t i=0;i<numberOfVault;i++){
                    if(bt_cp1252ToUtf8(&listeOfVaultName[i],listeOfVaultName[i])){
                        print_ERR(ERR_SYSTEM_MSG);
                        return 1;
                    }
                }
            #endif
            if(bt_boxVaults(listeOfVaultName,listeOfVaultSize,numberOfVault)){
                print_ERR("Something when wrong while printing bt_boxVaults");
                return 1;
            }

            break;
        }else if(bt_strcmp(argv[1],"password") == 0){
            // 1. On vérifie que le nombre de param est correcte
            if(argc > 3 ){
                print_WRN("Too many parameters (%d)",argc);
                return 1;
            }else if(argc < 3){
                print_WRN("Not enough parameters (%d)",argc);
                return 1;
            }

            // 2. On vérifie que le vault existe bien
            state = vaultAreadyCreated(argv[2]);
            if(state == -1){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }else if(state == 0){
                print_WRN("Vault '%s' does not exist",displayName);
                return 1;
            }

            // 3. On récupére son path
            char* vaultPath = NULL;
            state = getVaultPathFromName(&vaultPath,argv[2]);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }

            // 4. On demande le mdp du vault
            char* vaultPWD = NULL;
            char* buffer = NULL;
            printf("Enter the password of the vault : ");
            state = bt_fgetss(&vaultPWD);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                free(vaultPath);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                free(vaultPath);
                return 1;
            }

            // 5. On décrypte en mémoire pour eviter de l'avoir dans le DD
            uint8_t* vault_Encrypted_b = NULL;
            size_t vault_Encrypted_b_size;

            uint8_t* vault_Decrypted_b = NULL;
            size_t vault_Decrypted_b_size;
            state = readVault(&vault_Encrypted_b,&vault_Encrypted_b_size,vaultPath);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }else if(state == 2){
                print_ERR("Vault size >= 64 MO");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            state = AES_GCM_Decrypt(&vault_Decrypted_b,&vault_Decrypted_b_size,vault_Encrypted_b,vault_Encrypted_b_size,vaultPWD);
            if(AES_GCM_Decrypt_returnCodeHandler(state)){
                if(state == AES_ERR_MDP){
                    bt_logAction('@',displayName,1);
                }
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            // 6. On demande le nouveau mot de passe
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            print_INF("Remember or write down your master key, if you lost it NO RECOVERY POSSIBLE");
            printf("Enter the new password of the vault : ");
            state = bt_fgetss(&vaultPWD);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                free(vaultPath);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                free(vaultPath);
                return 1;
            }
            printf("Enter the new password of the vault again : ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            if(bt_strcmp(vaultPWD,buffer) != 0){
                print_WRN("The two password are not the same");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(buffer,bt_strlen(buffer));
                free(vaultPWD);
                free(buffer);
                free(vaultPath);
                return 1;
            }
            nukeString(buffer,bt_strlen(buffer));
            free(buffer);

            // 7. On ré-encrypte le vault avec le nouveau mdp
            uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
            free(vault_Encrypted_b);
            vault_Encrypted_b = NULL;
            state = AES_GCM_Encrypt(&vault_Encrypted_b,&vault_Encrypted_b_size,vault_Decrypted_b,vault_Decrypted_b_size,vaultPWD);
            if(AES_GCM_Encrypt_returnCodeHandler(state)){
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            state = writeVault(vault_Encrypted_b,vault_Encrypted_b_size,vaultPath);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            print_SUC("The vault '%s' have successfully change password",displayName);
            bt_logAction('!',displayName,1);

            uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
            free(vault_Encrypted_b);
            uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
            free(vault_Decrypted_b);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
        }else{

        }
        break;
    }
    case inf:{
        if(isOneOfThemEqual(argv[1],3,"--info","-i","-I")){
            if(bt_printInfo()){
                return 1;
            }
        }else if(isOneOfThemEqual(argv[1],3,"--help","-h","-H")){
            if(bt_printHelp()){
                return 1;
            }
        }else if(isOneOfThemEqual(argv[1],3,"--version","-v","-V")){
            if(bt_printVersion()){
                return 1;
            }
        }
        break;
    }

    default:
        break;
    }

    return 0;
}

static int fillUpEntryFromARGV(CShieldParams* e,char* argv[],int argc,methode m){
    int state = 0;
    int paramAPP = 0;
    int paramID = 0;
    int paramNOTE = 0;
    int paramTAGS = 0;
    size_t numOfTags = 0;
    char** tags = NULL;

    int paramNewApp = 0;
    int paramNewID = 0;
    int paramNewPwd = 0;

    int paramSEARCH = 0;
    int paramSHOW = 0;
    size_t numOfSearchedWord = 0;
    char** searchedWords = NULL;

    int paramHISTORY = 0;

    *e = (CShieldParams){0};

    if(m == gen){
        GenParameter genParam;
        state = getGenParam(&genParam);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        int len=genParam.lenght,up=genParam.uppercase,low=genParam.lowercase,dig=genParam.digits,sym=genParam.symbols;
        int lenP=0,upP=0,lowP=0,digP=0,symP=0;
        for(int i=2;i<argc;i++){
            if(isOneOfThemEqual(argv[i],2,"--length","-len")){
                if(lenP == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                    return 1;
                }
                lenP = 1;
                if(i+1 >= argc){
                    print_WRN("Lenght value missing after '%s' flags",argv[i]);
                    return 1;
                }
                if(argv[i+1][0] == '-'){
                    print_WRN("Must enter a valide number after '%s' flag",argv[i]);
                    return 1;
                }
                int lengthARGV;
                state = bt_strtoi(argv[i+1],&lengthARGV);
                if(state == 1){
                    print_WRN("Not an valide entry for '%s' value",argv[i]);
                    return 1;
                }else if(state == 2){
                    print_WRN("Not an integer");
                    return 1;
                }else if(state == 3){
                    print_WRN("Lenght too long to enter inside a integer (2147483648 char ... Seriously ?)");
                    return 1;
                }
                if(lengthARGV == 0){
                    print_WRN("You can't have a password with a length of 0 char");
                    return 1;
                }
                len = lengthARGV;
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--uppercase","-up")){
                if(upP == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                    return 1;
                }
                upP = 1; 
                if(up == 1){
                    up = 0;
                }else{
                    up = 1;
                }
            }else if(isOneOfThemEqual(argv[i],2,"--lowercase","-low")){
                if(lowP == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                    return 1;
                }
                lowP = 1; 
                if(low == 1){
                    low = 0;
                }else{
                    low = 1;
                }
            }else if(isOneOfThemEqual(argv[i],2,"--digits","-dig")){
                if(digP == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                    return 1;
                }
                digP = 1; 
                if(dig == 1){
                    dig = 0;
                }else{
                    dig = 1;
                }
            }else if(isOneOfThemEqual(argv[i],2,"--symbols","-sym")){
                if(symP == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                    return 1;
                }
                symP = 1; 
                if(sym == 1){
                    sym = 0;
                }else{
                    sym = 1;
                }
            }else{
                print_WRN("Flag '%s' unknow or useless while generating a password",argv[i]);
                return 1;
            }
        }

        if(!up && !low && !dig && !sym){
            print_WRN("No character set enabled, nothing to generate");
            return 1;
        }

        e->genParam.lenght = len;
        e->genParam.uppercase = up;
        e->genParam.lowercase = low;
        e->genParam.digits = dig;
        e->genParam.symbols = sym;
        return 0;
    }if(m == shw){
        if(argc == 4 && isOneOfThemEqual(argv[3],2,"--app","-a")){
            return 0;
        }
    }

    for(int i=3;i<argc;i++){
        if(isOneOfThemEqual(argv[i],2,"--app","-a")){
            if(i+1 >= argc || argv[i+1][0] == '-'){
                // Il manque l'app dans la commande
                print_WRN("App name missing after app balise");
                bt_deepFree(numOfTags, (void**)tags);
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            if(paramAPP == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags); 
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            paramAPP = 1;
            e->app = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--id","-i")){
            if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--id' is useless when changing the name of an app");
                    i++;
                    continue;
                }
            }
            if(i+1 >= argc || argv[i+1][0] == '-'){
                // Il manque l'id dans la commande
                print_WRN("ID name missing after ID balise");
                bt_deepFree(numOfTags, (void**)tags);
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            if(paramID == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            paramID = 1;
            e->id = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--note","-n")){
            if(m == dlt){
                print_WRN("The parameter '--note' is useless for the methode dlt");
                i++;
                continue;
            }else if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--note' is useless while changing the name of an app");
                    i++;
                    continue;
                }if(paramNewID == 1){
                    print_WRN("The parameter '--note' is useless while changing the name of an ID");
                    i++;
                    continue;
                }
            }else if(m == shw){
                print_WRN("The parameter '--note' is useless while exposing entry");
                i++;
                continue;
            }
            if(i+1 >= argc){
                // Il manque la note dans la commande
                print_WRN("Note missing after note balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramNOTE == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            paramNOTE = 1;
            e->note = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],6,"--tags","-t","--add-tags","-at","--remove-tags","-rt")){
            if(m == dlt){
                print_WRN("The parameter '--tags' is useless for the methode dlt");
                for(int j=i+1;j<argc;j++){
                    if((argv[j])[0] == '-'){
                        break;
                    }
                    i ++;
                }
                continue;
            }else if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--tags' is useless while changing the name of an app");
                }
                if(paramNewID == 1){
                    print_WRN("The parameter '--tags' is useless while changing the name of an ID");
                }
                if(paramNewApp == 1 || paramNewID == 1){
                    for(int j=i+1;j<argc;j++){
                        if((argv[j])[0] == '-'){
                            break;
                        }
                        i ++;
                    }
                    continue;
                }
                if(isOneOfThemEqual(argv[i],2,"--add-tags","-at")){
                    if(paramTAGS != 0){
                        print_WRN("Multiple tags flag use, one single methode allowed");
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                    paramTAGS = 2;
                    e->tagsMethode = paramTAGS;
                }else if(isOneOfThemEqual(argv[i],2,"--remove-tags","-rt")){
                    if(paramTAGS != 0){
                        print_WRN("Multiple tags flag use, one single methode allowed");
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                    paramTAGS = 3;
                    e->tagsMethode = paramTAGS;
                }else{
                    if(paramTAGS != 0){
                        print_WRN("Multiple tags flag use, one single methode allowed");
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                    paramTAGS = 1;
                    e->tagsMethode = paramTAGS;
                }
            }else if(m == crt){
                if(isOneOfThemEqual(argv[i],4,"--add-tags","-at","--remove-tags","-rt")){
                    print_WRN("Tags modifing methode does not apply with the create methode");
                    for(int j=i+1;j<argc;j++){
                        if((argv[j])[0] == '-'){
                            break;
                        }
                        i ++;
                    }
                    continue;
                }
                if(paramTAGS == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramTAGS = 1;
            }else if(m == shw){
                if(isOneOfThemEqual(argv[i],4,"--add-tags","-at","--remove-tags","-rt")){
                    print_WRN("Tags modifing methode does not apply with the show methode");
                    for(int j=i+1;j<argc;j++){
                        if((argv[j])[0] == '-'){
                            break;
                        }
                        i ++;
                    }
                    continue;
                }
                if(paramTAGS == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                    return 1;
                }
                if(paramHISTORY == 1){
                    print_WRN("The parameter '--tags' is useless while displaying the password history");
                }
                paramTAGS = 1;
            }
            // Calcule du nombre de tag + opeLogique si methode shw
            char opeLogique = '&';
            int containOperator = 0;
            for(int j=i+1;j<argc;j++){
                if((argv[j])[0] == '-'){
                    if(isOneOfThemEqual(argv[j],2,"--and","--or")){
                        if(m != shw){
                            print_WRN("Flags '--and' or '--or' are valid only for methode show");
                            bt_deepFree(numOfTags, (void**)tags);
                            bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                            return 1;
                        }else{
                            if(bt_strcmp(argv[j],"--and") == 0){
                                if(!containOperator){
                                    containOperator = 1;
                                    numOfTags ++;
                                    continue;
                                }else{
                                    print_WRN("One single operator is autorise inside --tags flag");
                                    bt_deepFree(numOfTags, (void**)tags);
                                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                                    return 1;
                                }
                            }else if(bt_strcmp(argv[j],"--or") == 0){
                                if(!containOperator){
                                    opeLogique = '|';
                                    containOperator = 1;
                                    numOfTags ++;
                                    continue;
                                }else{
                                    print_WRN("One single operator is autorise inside --tags flag");
                                    bt_deepFree(numOfTags, (void**)tags);
                                    bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                                    return 1;
                                }
                            }
                        }
                    }
                    break;
                }
                numOfTags ++;
            }
            if(numOfTags-containOperator == 0){
                print_WRN("No tag provided after tags balise");
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            char** tmp = realloc(tags,(numOfTags-containOperator) * sizeof(char*));
            if(tmp == NULL){
                print_ERR("Error while allocating tags memory");
                bt_deepFree(numOfTags-containOperator, (void**)tags);
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            tags = tmp;
            for(size_t j=0;j<numOfTags-containOperator;j++){
                tags[j] = NULL;
            }
            // Allocation de tout les tags
            size_t indexTags = 0;
            for(size_t j=0;j<numOfTags;j++){
                if(isOneOfThemEqual(argv[i+1+j],2,"--and","--or")){
                    continue;
                }else{
                    if(isTagAlreadyHere(tags,indexTags,argv[i+1+j])){
                        print_WRN("Duplicated tag ('%s')",argv[i+1+j]);
                        bt_deepFree(numOfTags-containOperator, (void**)tags);
                        bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                        return 1;
                    }
                
                    state = bt_strcpy(&tags[indexTags], argv[i+1+j]);
                    if(state == 1){
                        print_ERR("Error while allocating a tag memory");
                        bt_deepFree(numOfTags-containOperator, (void**)tags);
                        bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                        return 1;
                    }
                    indexTags ++;
                }
            }

            i += numOfTags;
            numOfTags -= containOperator;
            e->OpeLogTAGS = opeLogique;
            e->nbOfTags = numOfTags;
            e->tags = tags;
        }else if(isOneOfThemEqual(argv[i],2,"--search","-se")){
            // Calculer le nombre de word + opé potentiel
            numOfSearchedWord = 0;
            char opeLogique = '&';
            int containOperator = 0;
            for(int j=i+1;j<argc;j++){
                if((argv[j])[0] == '-'){
                    if(bt_strcmp(argv[j],"--and") == 0){
                        if(!containOperator){
                            containOperator = 1;
                            numOfSearchedWord ++;
                            continue;
                        }else{
                            print_WRN("One single operator is autorise inside --search flag");
                            bt_deepFree(numOfTags, (void**)tags);
                            bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                            return 1;
                        }
                    }else if(bt_strcmp(argv[j],"--or") == 0){
                        if(!containOperator){
                            opeLogique = '|';
                            containOperator = 1;
                            numOfSearchedWord ++;
                            continue;
                        }else{
                            print_WRN("One single operator is autorise inside --search flag");
                            bt_deepFree(numOfTags, (void**)tags);
                            bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                            return 1;
                        }
                    }
                    break;
                }
                numOfSearchedWord ++;
            }
            if(m == crt){
                print_WRN("The parameter '--search' is useless while creating entry");
                i+= numOfSearchedWord;
                continue;
            }else if(m == mdf){
                print_WRN("The parameter '--search' is useless while modifying an entry");
                i+= numOfSearchedWord;
                continue;
            }else if(m == dlt){
                print_WRN("The parameter '--search' is useless while deleting entry");
                i+= numOfSearchedWord;
                continue;
            }
            if(paramSEARCH == 1){
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            paramSEARCH = 1;

            if(numOfSearchedWord-containOperator == 0){
                print_WRN("No word provided after search balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            char** tmp = realloc(searchedWords,(numOfSearchedWord-containOperator) * sizeof(char*));
            if(tmp == NULL){
                print_ERR("Error while allocating words memory");
                bt_deepFree(numOfSearchedWord, (void**)searchedWords);
                bt_deepFree(numOfTags,(void**)tags);
                return 1;
            }
            searchedWords = tmp;
            for(size_t j=0;j<numOfSearchedWord-containOperator;j++){
                searchedWords[j] = NULL;
            }
            size_t indexSearchedWord = 0;
            for(size_t j=0;j<numOfSearchedWord;j++){
                if(isOneOfThemEqual(argv[i+1+j],2,"--and","--or")){
                    continue;
                }else{
                    state = bt_strcpy(&searchedWords[indexSearchedWord], argv[i+1+j]);
                    if(state == 1){
                        print_ERR("Error while allocating a words memory");
                        bt_deepFree(numOfSearchedWord-containOperator, (void**)searchedWords);
                        bt_deepFree(numOfTags,(void**)tags);
                        return 1;
                    }
                    indexSearchedWord++;
                }

            }

            i += numOfSearchedWord;
            e->OpeLogWORD = opeLogique;
            e->nbOfSearchedWord = numOfSearchedWord-containOperator;
            e->searchedWords = searchedWords;
        }else if(isOneOfThemEqual(argv[i],2,"--show","-sh")){
            if(m == crt){
                print_WRN("The parameter '--show' is useless while creating entry");
                continue;
            }else if(m == mdf){
                print_WRN("The parameter '--show' is useless while modifying an entry");
                continue;
            }else if(m == dlt){
                print_WRN("The parameter '--show' is useless while deleting entry");
                continue;
            }
            if(paramSHOW == 1){
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            paramSHOW = 1;
            e->show = 1;
        }else if(isOneOfThemEqual(argv[i],2,"--password","-p")){
            if(m == dlt || m == shw){
                if(m == dlt){
                    print_WRN("The parameter '--password' is useless while deleting an entry");
                }else{
                    print_WRN("The parameter '--password' is useless while exposing an entry");
                }
                if(i+1 < argc && argv[i+1][0] != '-'){
                    print_INF("Password is NEVER entered through parameters");
                    i++;
                }
                continue;
            }

            if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--password' is useless while changing the name of an app");
                }if(paramNewID == 1){
                    print_WRN("The parameter '--password' is useless while changing the name of an ID");
                }
            }

            if(paramNewPwd == 1){
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(i+1 < argc){
                if(argv[i+1][0] != '-'){
                    print_WRN("No password goes through parameters, secure input done later");
                    i++;
                }
            }
            paramNewPwd = 1;
            e->newPassword = 1;
            continue;
        }else if(isOneOfThemEqual(argv[i],2,"--history","-h")){
            if(m != shw){
                print_WRN("Flag '--history' useless outside shw methode");
                continue;
            }
            if(paramHISTORY == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags); 
                bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
                return 1;
            }
            paramHISTORY = 1;
            if(paramNOTE == 1 || paramTAGS == 1){
                print_WRN("Parameter outside '--app' and '--id' is useless with the flag '--history'");
            }
            e->history = 1;
        }else if(m == mdf){
            if(isOneOfThemEqual(argv[i],2,"--new-app","-na")){
                if(i+1 >= argc || argv[i+1][0] == '-'){
                    // Il manque le nom de la nouvelle app
                    print_WRN("App name missing after new app name balise");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewID == 1){
                    print_WRN("conflict of parameter, '--new-id' already typed");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewApp == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramNewApp = 1;
                if(paramID == 1 || paramNOTE == 1 || paramTAGS != 0 || paramNewPwd == 1){
                    print_WRN("All parameter outside '--app' and '--new-app' is useless while changing the name of an app");
                }
                e->newAppName = argv[i+1];
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--new-id","-ni")){
                if(i+1 >= argc || argv[i+1][0] == '-'){
                    // Il manque le nouvel ID dans la commande
                    print_WRN("ID missing after new ID name balise");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewApp == 1){
                    print_WRN("conflict of parameter, '--new-app' already typed");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewID == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramNewID = 1;
                if(paramNOTE == 1 || paramTAGS != 0 || paramNewApp == 1 || paramNewPwd == 1){
                    print_WRN("All parameter outside '--app','--id' and '--new-id' is useless while changing the ID of an entry");
                }
                e->newIDName = argv[i+1];
                i++;
            }else{
                // Commande non reconnue
                print_WRN("Argument '%s' does not exist for the command '%s'",argv[i],argv[1]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
        }else{
            // Commande non reconnue
            print_WRN("Argument '%s' does not exist for the command '%s'",argv[i],argv[1]);
            bt_deepFree(numOfTags, (void**)tags);
            bt_deepFree(e->nbOfSearchedWord,(void**)searchedWords);
            return 1;
        }
    }

    // Vérification selon le type de methode
    if(m == crt){
        if(paramAPP == 0 && paramID == 0){
            print_WRN("--app and --id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }else if(paramAPP == 0){
            print_WRN("--app parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }else if(paramID == 0){
            print_WRN("--id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
    }if(m == dlt){
        if(paramAPP == 0){
            print_WRN("--app parameter missing");
            return 1;
        }
    }if(m == mdf){
        if(paramAPP == 0){
            print_WRN("--app parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
        if(paramNewID == 1 && paramID == 0){
            print_WRN("--id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
        if(paramNewApp == 0 && paramNewID == 0 && paramID == 0){
            print_WRN("--id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
        if(paramNewApp == 0 && paramNewID == 0 && paramNOTE == 0 && paramTAGS == 0 && paramNewPwd == 0){
            print_WRN("Nothing to modify, use '--note', '--tags', '--add-tags', '--remove-tags', '--password', '--new-app' or '--new-id'");
            return 1;
        }

        if(paramNewApp == 1){
            e->id = NULL;
            e->note = NULL;
            bt_deepFree(e->nbOfTags,(void**)tags);
            e->tags = NULL;
            e->nbOfTags = 0;
            e->newPassword = 0;
            e->tagsMethode = 0;
        }else if(paramNewID == 1){
            e->note = NULL;
            bt_deepFree(e->nbOfTags,(void**)tags);
            e->tags = NULL;
            e->nbOfTags = 0;
            e->newPassword = 0;
            e->tagsMethode = 0;
        }
    }if(m == shw){
        if(paramHISTORY == 1){
            if(paramAPP == 0){
                print_WRN("--app parameter missing");
                bt_deepFree(e->nbOfTags,(void**)tags);
                return 1;
            }else if(paramID == 0){
                print_WRN("--id parameter missing");
                bt_deepFree(e->nbOfTags,(void**)tags);
                return 1;
            }
        }
    }

    return 0;
}

static int witchBox(CShieldParams p){    
    if(p.history == 1){
        return 7;
    }else if(p.tags != NULL){
        return 3;
    }else if(p.searchedWords != NULL){
        return 4;
    }else if(p.app != NULL && p.id != NULL){
        return 1;
    }else if(p.app != NULL && p.id == NULL){
        return 2;
    }else if(p.app == NULL && p.id == NULL){
        return 6;
    }
    return 0;
}

int AES_GCM_Decrypt_returnCodeHandler(int code){
    if(code == AES_ERR_PARAM){
        print_ERR("One of the parameter of AES_GCM_Decrypt is a null pointer");
        return 1;
    }else if(code == AES_ERR_VERSION){
        print_WRN("The encrypting file version is not the same as AES version");
        return 1;
        // A changée pour compatiblitée plus tard
    }else if(code == AES_ERR_MEMOIRE){
        print_ERR("Error occured while allocating memory");
        return 1;
    }else if(code == AES_ERR_MDP){
        print_WRN("Wrong password");

        return 1;
    }else if(code == AES_ERR_AUTH){
        print_ERR("Vault altered while encrypted");
        return 1;
    }else if(code == AES_ERR_FORMAT){
        print_ERR("The vault file is not valid encrypted data (too short or corrupted)");
        return 1;
    }else if(code != AES_OK){
        print_ERR("An unknow error occured...");
        return 1;
    }

    return 0;
}

int AES_GCM_Encrypt_returnCodeHandler(int code){
    if(code == AES_ERR_PARAM){
        print_ERR("One of the parameter of AES_GCM_Encrypt is a null pointer");
        return 1;
    }else if(code == AES_ERR_TAILLE){
        print_ERR("The size of the vault exed 64 GO");
        return 1;
    }else if(code == AES_ERR_ALEA){
        print_ERR("An error whith random occured (urandom or BCryptGenRandom)");
        return 1;
    }else if(code == AES_ERR_MEMOIRE){
        print_ERR("Error occured while allocating memory");
        return 1;
    }else if(code != AES_OK){
        print_ERR("An unknow error occured...");
        return 1;
    }

    return 0;
}

static int isTagAlreadyHere(char** tags,size_t numberOfTags,char* newTag){
    for(size_t i=0;i<numberOfTags;i++){
        if(bt_strcmp(tags[i],newTag) == 0){
            return 1;
        }
    }

    return 0;
}

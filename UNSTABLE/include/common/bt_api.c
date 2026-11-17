#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <time.h>

#include "cson.h"

#include "bt_api.h"
#include "bt_utils.h"
#include "bt_log.h"

int addEntry(JsonValue *vaultRoot,CShildParams entry){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL or not an object)");
        return 1;
    }
    if(entry.app == NULL || entry.id == NULL){
        LOG_ERROR("App name or ID null");
        return 1;
    }
    int state = 0;
    size_t indexor = 0;
    // Vérification des version 
    double versionCShild = getVersionCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    double versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    indexor = getIndexFromObjectWithKey(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
    }
    // L'application existe t'il ?
    JsonValue *apps_p = &vaultRoot->value.object->listeOfPair[indexor].value;
    size_t indexApp = getIndexFromObjectWithKey(vaultRoot->value.object->listeOfPair[indexor].value.value.object,entry.app);
    if(indexApp == (size_t)-1){
        // L'app n'existe pas
        JsonValue newApp = initJsonValue(JSON_OBJECT);
        if(newJsonObject(&newApp)){
            LOG_ERROR("Creation of an object failed (newJsonObject)");
            freeValue(newApp);
            return 1;
        }
        JsonValue newID = initJsonValue(JSON_OBJECT);
        if(newJsonObject(&newID)){
            LOG_ERROR("Creation of an object failed (newJsonObject)");
            freeValue(newApp);
            return 1;
        }
        if(generateNewBlankEntry(newID.value.object)){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Generation of a blank entry failed (generateNewBlankEntry)");
            return 1;
        }
        state = fillUpWithEntry(newID.value.object,entry);
        if(state == 1){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Filling of an object from an entry failed (fillUpWithEntry)");
            return 1;
        }else if(state == 2){
            freeValue(newApp);
            freeValue(newID);
            return 2;
        }
        if(addToObject(newApp.value.object,entry.id,newID,0)){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Adding a new value in an object failed (addToObject)");
            return 1;
        }
        if(addToObject(apps_p->value.object,entry.app,newApp,apps_p->value.object->nbOfElement)){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Adding a new value in an object failed (addToObject)");
            return 1;
        }
        freeValue(newApp);
        freeValue(newID);
    }else{
        JsonValue *IDs_p = &apps_p->value.object->listeOfPair[indexApp].value;
        size_t indexID = getIndexFromObjectWithKey(IDs_p->value.object,entry.id);
        if(indexID == (size_t)-1){
            // L'ID n'existe pas
            JsonValue newID = initJsonValue(JSON_OBJECT);
            if(newJsonObject(&newID)){
                LOG_ERROR("Creation of an object failed (newJsonObject)");
                return 1;
            }
            if(generateNewBlankEntry(newID.value.object)){
                freeValue(newID);
                LOG_ERROR("Generation of a blank entry failed (generateNewBlankEntry)");
                return 1;
            }
            state = fillUpWithEntry(newID.value.object,entry);
            if(state == 1){
                freeValue(newID);
                LOG_ERROR("Filling of an object from an entry failed (fillUpWithEntry)");
                return 1;
            }else if(state == 2){
                freeValue(newID);
                return 2;
            }
            if(addToObject(IDs_p->value.object,entry.id,newID,IDs_p->value.object->nbOfElement)){
                freeValue(newID);
                LOG_ERROR("Adding a new value in an object failed (addToObject)");
                return 1;
            }
            freeValue(newID);
        }else{  
            return 3;
        }
    }

    return 0;
}


int removeEntry(JsonValue *vaultRoot,CShildParams entry,int* numberOfEntryRemoved){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT || numberOfEntryRemoved == NULL){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL,numberOfEntryRemoved == NULL or not an object)");
        return 1;
    }
    if(entry.app == NULL){
        LOG_ERROR("App name null");
        return 1;
    }
    *numberOfEntryRemoved = 0;
    int state = 0;
    size_t indexor = 0;
    double versionCShild = getVersionCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    double versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    indexor = getIndexFromObjectWithKey(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
    }
    // L'application existe t'elle ?
    JsonValue *apps_p = &vaultRoot->value.object->listeOfPair[indexor].value;
    if(apps_p->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - Application value is not an object");
        return 1;
    }
    size_t indexApp = getIndexFromObjectWithKey(apps_p->value.object,entry.app);
    if(indexApp == (size_t)-1){
        // L'app n'existe pas
        return 2;
    }

    JsonValue *IDs_p = &apps_p->value.object->listeOfPair[indexApp].value;
    if(IDs_p->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - ID value is not an object");
        return 1;
    }
    if(entry.id == NULL){
        // On détruit TOUT l'app
        *numberOfEntryRemoved = apps_p->value.object->listeOfPair[indexApp].value.value.object->nbOfElement;
        state = removeFromObject(apps_p->value.object,indexApp);
        if(state == 1){
            LOG_ERROR("Removing a value in an object failed (removeFromObject)");
            return 1;
        }
        return 0;
    }else{
        // On détruit un compte
        size_t indexID = getIndexFromObjectWithKey(IDs_p->value.object,entry.id);
        if(indexID == (size_t)-1){
            // L'ID n'existe pas
            return 3;
        }
        *numberOfEntryRemoved = 1;
        state = removeFromObject(IDs_p->value.object,indexID);
        if(state == 1){
            LOG_ERROR("Removing a value in an object failed (removeFromObject)");
            return 1;
        }
        if(IDs_p->value.object->nbOfElement == 0){
            state = removeFromObject(apps_p->value.object,indexApp);
            if(state == 1){
                LOG_ERROR("Removing a value in an object failed (removeFromObject)");
                return 1;
            }
            // Le nom de l'app existe deja
            return 4;
        }
    }

    return 0;
}

int modEntry(JsonValue *vaultRoot,CShildParams entry,size_t* indexBadTag){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL or not an object)");
        return 1;
    }
    if(entry.newPassword == 1 && entry.pwd == NULL){
        LOG_ERROR("Corrupted pointer (entry.newPassword == 1 but entry.pwd == NULL)");
        return 1;
    }
    if(entry.app == NULL){
        LOG_ERROR("App name null");
        return 1;
    }
    if(indexBadTag == NULL){
        LOG_ERROR("Corrupted pointer (indexBadTag == NULL)");
        return 1;
    }

    int state = 0;
    size_t indexor = 0;
    double versionCShild = getVersionCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    double versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    indexor = getIndexFromObjectWithKey(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
    }
    // L'application existe t'elle ?
    JsonValue *apps_p = &vaultRoot->value.object->listeOfPair[indexor].value;
    if(apps_p->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - 'apps' value is not an object");
        return 1;
    }
    size_t indexApp = getIndexFromObjectWithKey(apps_p->value.object,entry.app);
    if(indexApp == (size_t)-1){
        // L'app n'existe pas
        return 2;
    }
    if(entry.newAppName != NULL){
        if(getIndexFromObjectWithKey(apps_p->value.object,entry.newAppName) != (size_t)-1){
            // Nom d'app deja pris
            return 4;
        }
        JsonPair newPaire;
        newPaire.key = entry.newAppName;
        newPaire.value = apps_p->value.object->listeOfPair[indexApp].value;
        state = modifyObject(apps_p->value.object,newPaire,indexApp);
        if(state == 1){
            LOG_ERROR("Modifing value in an object failed (modifyObject)");
            return 1;
        }
        return 0;
    }else{
        JsonValue *IDs_p = &apps_p->value.object->listeOfPair[indexApp].value;
        if(IDs_p->type != JSON_OBJECT){
            LOG_ERROR("JSON of the vault altered - ID value is not an object");
            return 1;
        }
        if(entry.id == NULL){
            LOG_ERROR("ID name null");
            return 1;
        }
        size_t indexID = getIndexFromObjectWithKey(IDs_p->value.object,entry.id);
        if(indexID == (size_t)-1){
            // L'ID n'existe pas
            return 3;
        }
        if(entry.newIDName != NULL){
            if(getIndexFromObjectWithKey(IDs_p->value.object,entry.newIDName) != (size_t)-1){
                // Le nouvelle ID existe deja
                return 5;
            }
            JsonPair newPaire;
            newPaire.key = entry.newIDName;
            newPaire.value = IDs_p->value.object->listeOfPair[indexID].value;
            state = modifyObject(IDs_p->value.object,newPaire,indexID);
            if(state == 1){
                LOG_ERROR("Modifing value in an object failed (modifyObject)");
                return 1;
            }
            return 0;
        }else{
            JsonObject* selectedObject = IDs_p->value.object->listeOfPair[indexID].value.value.object;
            if(entry.note != NULL){
                size_t indexNote = getIndexFromObjectWithKey(selectedObject,"note");
                if(indexNote == (size_t)-1){
                    LOG_ERROR("JSON of the vault altered - key 'note' not found");
                    return 1;
                }
                char* buffeurNote = NULL;
                state = bt_strcpy(&buffeurNote,entry.note);
                if(state == 1){
                    LOG_ERROR("Copy of a string failed (bt_strcpy)");
                    return 1;
                }
                freeValue(selectedObject->listeOfPair[indexNote].value);
                selectedObject->listeOfPair[indexNote].value.value.string = buffeurNote;
            }
            if(entry.newPassword == 1){
                state = modPassword(selectedObject,entry.pwd);
                if(state == 1){
                    return 1;
                }else if(state == 2){
                    // Nouveau mot de passe vide
                    return 6;
                }
            }
            if(entry.tags != NULL){
                size_t indexTags = getIndexFromObjectWithKey(selectedObject,"tags");
                if(indexTags == (size_t)-1){
                    LOG_ERROR("JSON of the vault altered - key 'tags' not found");
                    return 1;
                }

                if(entry.tagsMethode == 1){
                    JsonValue newTags = initJsonValue(JSON_ARRAY);
                    if(newJsonArray(&newTags)){
                        LOG_ERROR("Creation of an array failed (newJsonArray)");
                        return 1;
                    }
                    for(size_t i=0;i<entry.nbOfTags;i++){
                        JsonValue tag = initJsonValue(JSON_STRING);
                        tag.value.string = entry.tags[i];
                        state = addToArray(newTags.value.array,tag,i);
                        if(state == 1){
                            LOG_ERROR("Adding a new value in an array failed (addToArray)");
                            freeValue(newTags);
                            return 1;
                        }
                    }
                    // Affectation du nouvelle array -> On écrase l'ancien !!! 
                    freeValue(selectedObject->listeOfPair[indexTags].value);
                    selectedObject->listeOfPair[indexTags].value.value.array = newTags.value.array;
                }else if(entry.tagsMethode == 2){
                    size_t nomberDeTag = selectedObject->listeOfPair[indexTags].value.value.array->nbOfElement;
                    for(size_t i = nomberDeTag;i<nomberDeTag+entry.nbOfTags;i++){
                        JsonValue newtag = initJsonValue(JSON_STRING);
                        newtag.value.string = entry.tags[i-nomberDeTag];
                        if(getIndexFromArray(selectedObject->listeOfPair[indexTags].value.value.array,newtag) != (size_t)-1){
                            // Le tag existe deja
                            *indexBadTag = i-nomberDeTag;
                            return 7;
                        }
                        state = addToArray(selectedObject->listeOfPair[indexTags].value.value.array,newtag,i);
                        if(state == 1){
                            LOG_ERROR("Adding a new value in an array failed (addToArray)");
                            return 1;
                        }
                    }
                }else if(entry.tagsMethode == 3){
                    for(size_t i = 0;i<entry.nbOfTags;i++){
                        JsonValue targetTag = initJsonValue(JSON_STRING);
                        targetTag.value.string = entry.tags[i];
                        size_t indexToErase = getIndexFromArray(selectedObject->listeOfPair[indexTags].value.value.array,targetTag);
                        if(indexToErase == (size_t)-1){
                            // Le tag n'existe pas
                            *indexBadTag = i;
                            return 8;
                        }
                        state = removeFromArray(selectedObject->listeOfPair[indexTags].value.value.array,indexToErase);
                        if(state == 1){
                            LOG_ERROR("Removing a value in an array failed (removeFromArray)");
                            return 1;
                        }
                    }
                }
            }
            size_t indexUpdated_at = getIndexFromObjectWithKey(selectedObject,"updated_at");
            if(indexUpdated_at == (size_t)-1){
                LOG_ERROR("JSON of the vault altered - key 'updated_at' not found");
                return 1;
            }
            char* updated_at_str = NULL;
            if(getTime(&updated_at_str)){
                LOG_ERROR("Impossible to fetch actual time (getTime)");
                return 1;
            }
            freeValue(selectedObject->listeOfPair[indexUpdated_at].value);
            selectedObject->listeOfPair[indexUpdated_at].value.value.string = updated_at_str;
        }
    }

    return 0;
}

int modPassword(JsonObject *obj,char* newPassword){
    int state = 0;
    if(bt_strlen(newPassword) == 0){
        return 2;
    }
    size_t indexPassword = getIndexFromObjectWithKey(obj,"password");
    if(indexPassword == (size_t)-1){
        LOG_ERROR("JSON altered or corrupted, key 'password' not found");
        return 1;
    }
    size_t indexHistory = getIndexFromObjectWithKey(obj,"password_history");
    if(indexHistory == (size_t)-1){
        LOG_ERROR("JSON altered or corrupted, key 'password_history' not found");
        return 1;
    }

    if(bt_strlen(obj->listeOfPair[indexPassword].value.value.string) > 0){
        JsonArray* arrayHistory_p = obj->listeOfPair[indexHistory].value.value.array;

        JsonValue oldPassword_v = initJsonValue(JSON_OBJECT);
        if(newJsonObject(&oldPassword_v)){
            LOG_ERROR("Creation of an object failed (newJsonObject)");
            return 1;
        }
        char* password = NULL;
        // get the old password
        state = bt_strcpy(&password,obj->listeOfPair[indexPassword].value.value.string);
        if(state == 1){
            LOG_ERROR("Copy of a string failed (bt_strcpy)");
            freeValue(oldPassword_v);
            return 1;
        }
        JsonValue password_v = initJsonValue(JSON_STRING);
        password_v.value.string = password;
        // get the time
        char* date = NULL;
        state = getTime(&date);
        if(state == 1){
            freeValue(password_v);
            freeValue(oldPassword_v);
            LOG_ERROR("Impossible to fetch actual time (getTime)");
            return 1;
        }

        JsonValue date_v = initJsonValue(JSON_STRING);
        date_v.value.string = date;

        state = addToObject(oldPassword_v.value.object,"password",password_v,0);
        freeValue(password_v);
        if(state == 1){
            freeValue(date_v);
            freeValue(oldPassword_v);
            LOG_ERROR("Adding a new value in an object failed (addToObject)");
            return 1;
        }
        state = addToObject(oldPassword_v.value.object,"changed_at",date_v,1);
        freeValue(date_v);
        if(state == 1){
            freeValue(oldPassword_v);
            LOG_ERROR("Adding a new value in an object failed (addToObject)");
            return 1;
        }

        size_t numberOfElementHistory  = obj->listeOfPair[indexHistory].value.value.array->nbOfElement;
        state = addToArray(arrayHistory_p,oldPassword_v,numberOfElementHistory);
        freeValue(oldPassword_v);
        if(state == 1){
            LOG_ERROR("Adding a new value in an array failed (addToArray)");
            return 1;
        }
    }

    char* buffer = NULL;
    state = bt_strcpy(&buffer,newPassword);
    if(state == 1){
        LOG_ERROR("Copy of a string failed (bt_strcpy)");
        return 1;
    }
    char* oldPassword_str = obj->listeOfPair[indexPassword].value.value.string;
    stringToZero(oldPassword_str,bt_strlen(oldPassword_str)+1);
    stringToZero(newPassword,bt_strlen(newPassword)+1);
    free(oldPassword_str);

    obj->listeOfPair[indexPassword].value.value.string = buffer;

    return 0;
}

// Remplit les champs de e à partir de entries (la valeur JSON d'une entrée : password, note, tags, created_at, updated_at) :
// pwd (seulement si show == 1, sinon il reste NULL), note, tags + nbOfTags, created et updated sont des copies à libérer par l'appelant.
// e doit être à zéro avant l'appel, et app / id ne sont PAS remplis ici : l'appelant les copie après (sinon ils seraient libérés avec le reste en cas d'erreur).
// Renvoie 0 si tout est copié, 1 en cas d'erreur (paramètre invalide, vault altéré, mémoire...) : e est alors remis à zéro, il n'y a rien à libérer.
int getEntry(JsonValue entries,CShildEntry *e,int show){
    if(e == NULL){
        LOG_ERROR("Corrupted pointer (e == NULL)");
        return 1;
    }
    if(entries.type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - entry value is not an object");
        return 1;
    }

    if(show == 1){
        size_t indexPassword = getIndexFromObjectWithKey(entries.value.object,"password");
        if(indexPassword == (size_t)-1){
            LOG_ERROR("JSON of the vault altered - 'password' is not found in entry object");
            nukeString(e->pwd,bt_strlen(e->pwd));
            bt_deepFree(e->nbOfTags,(void**)e->tags);
            bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
            *e = (CShildEntry){0};
            return 1;
        }
        if(bt_strcpy(&e->pwd,entries.value.object->listeOfPair[indexPassword].value.value.string)){
            LOG_ERROR("Copy of a string failed (bt_strcpy)");
            nukeString(e->pwd,bt_strlen(e->pwd));
            bt_deepFree(e->nbOfTags,(void**)e->tags);
            bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
            *e = (CShildEntry){0};
            return 1;
        }
    }
    size_t indexNote = getIndexFromObjectWithKey(entries.value.object,"note");
    if(indexNote == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - 'note' is not found in entry object");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    if(bt_strcpy(&e->note,entries.value.object->listeOfPair[indexNote].value.value.string)){
        LOG_ERROR("Copy of a string failed (bt_strcpy)");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    size_t indexTags = getIndexFromObjectWithKey(entries.value.object,"tags");
    if(indexTags == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - 'tags' is not found in entry object");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    size_t nbOfTags = entries.value.object->listeOfPair[indexTags].value.value.array->nbOfElement;
    e->nbOfTags = nbOfTags;
    e->tags = calloc(e->nbOfTags,sizeof(char*));
    if(e->tags == NULL && nbOfTags > 0){
        LOG_ERROR("Error while allocating memory (e->tags = calloc)");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    for(size_t i=0;i<nbOfTags;i++){
        if(bt_strcpy(&e->tags[i],entries.value.object->listeOfPair[indexTags].value.value.array->listeOfValue[i].value.string)){
            LOG_ERROR("Copy of a string failed (bt_strcpy)");
            nukeString(e->pwd,bt_strlen(e->pwd));
            bt_deepFree(e->nbOfTags,(void**)e->tags);
            bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
            *e = (CShildEntry){0};
            return 1;
        }
    }
    size_t indexCreated_at = getIndexFromObjectWithKey(entries.value.object,"created_at");
    if(indexCreated_at == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - 'created_at' is not found in entry object");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    if(bt_strcpy(&e->created,entries.value.object->listeOfPair[indexCreated_at].value.value.string)){
        LOG_ERROR("Copy of a string failed (bt_strcpy)");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    size_t indexUpdated_at = getIndexFromObjectWithKey(entries.value.object,"updated_at");
    if(indexUpdated_at == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - 'updated_at' is not found in entry object");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    if(bt_strcpy(&e->updated,entries.value.object->listeOfPair[indexUpdated_at].value.value.string)){
        LOG_ERROR("Copy of a string failed (bt_strcpy)");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }

    return 0;
}

int getAllFromApp(JsonValue* vaultRoot,CShildEntry** e,size_t* numberOfEntry,CShildParams p){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL or not an object)");
        return 1;
    }
    if(e == NULL){
        LOG_ERROR("Corrupted pointer (e == NULL)");
        return 1;
    }
    if(p.app == NULL){
        LOG_ERROR("App name not provided (e->app == NULL)");
        return 1;
    }
    if(numberOfEntry == NULL){
        LOG_ERROR("Corrupted pointer (numberOfEntry == NULL)");
        return 1;
    }

    size_t indexor = 0;
    double versionCShild = getVersionCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    double versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    indexor = getIndexFromObjectWithKey(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
    }
    JsonValue* apps_v = &vaultRoot->value.object->listeOfPair[indexor].value;
    if(apps_v->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - 'apps' value is not an object");
        return 1;
    }

    // L'app existe ?
    size_t indexApp = getIndexFromObjectWithKey(apps_v->value.object,p.app);
    if(indexApp == (size_t)-1){
        // L'app n'existe pas 
        return 2;
    }
    JsonValue* entry_v = &apps_v->value.object->listeOfPair[indexApp].value;
    if(entry_v->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - entry value is not an object");
        return 1;
    }

    *numberOfEntry = entry_v->value.object->nbOfElement;
    *e = calloc(*numberOfEntry,sizeof(CShildEntry));
    if(*e == NULL){
        *numberOfEntry = 0;
        LOG_ERROR("Error while allocating memory (*e = calloc(numberOfEntry,sizeof(CShildEntry)))");
        return 1;
    }
    for(size_t i=0;i<*numberOfEntry;i++){
        (*e)[i] = (CShildEntry){0};
        int state = getEntry(entry_v->value.object->listeOfPair[i].value,&(*e)[i],p.show);
        if(state == 1){
            for(size_t j=0;j<=i;j++){
                nukeString((*e)[j].pwd,bt_strlen((*e)[j].pwd));
                bt_deepFree((*e)[j].nbOfTags,(void**)(*e)[j].tags);
                bt_multiFree(6,(*e)[j].app,(*e)[j].id,(*e)[j].pwd,(*e)[j].note,(*e)[j].created,(*e)[j].updated);
            }
            free(*e);
            *e = NULL;
            *numberOfEntry = 0;
            return 1;
        }

        if(bt_strcpy(&(*e)[i].app,p.app)){
            for(size_t j=0;j<=i;j++){
                nukeString((*e)[j].pwd,bt_strlen((*e)[j].pwd));
                bt_deepFree((*e)[j].nbOfTags,(void**)(*e)[j].tags);
                bt_multiFree(6,(*e)[j].app,(*e)[j].id,(*e)[j].pwd,(*e)[j].note,(*e)[j].created,(*e)[j].updated);
            }
            free(*e);
            *e = NULL;
            *numberOfEntry = 0;
            return 1;
        }
        if(bt_strcpy(&(*e)[i].id,entry_v->value.object->listeOfPair[i].key)){
            for(size_t j=0;j<=i;j++){
                nukeString((*e)[j].pwd,bt_strlen((*e)[j].pwd));
                bt_deepFree((*e)[j].nbOfTags,(void**)(*e)[j].tags);
                bt_multiFree(6,(*e)[j].app,(*e)[j].id,(*e)[j].pwd,(*e)[j].note,(*e)[j].created,(*e)[j].updated);
            }
            free(*e);
            *e = NULL;
            *numberOfEntry = 0;
            return 1;
        }
    }

    return 0;
}

int getSingleEntry(JsonValue* vaultRoot,CShildEntry* e,CShildParams p){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL or not an object)");
        return 1;
    }
    if(e == NULL){
        LOG_ERROR("Corrupted pointer (e == NULL)");
        return 1;
    }
    if(p.app == NULL){
        LOG_ERROR("App name not provided (e->app == NULL)");
        return 1;
    }
    if(p.id == NULL){
        LOG_ERROR("ID not provided (e->id == NULL)");
        return 1;
    }

    size_t indexor = 0;
    double versionCShild = getVersionCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    double versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    *e = (CShildEntry){0};
    indexor = getIndexFromObjectWithKey(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
    }
    JsonValue* apps_v = &vaultRoot->value.object->listeOfPair[indexor].value;
    if(apps_v->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - 'apps' value is not an object");
        return 1;
    }
    // L'app existe ?
    size_t indexApp = getIndexFromObjectWithKey(apps_v->value.object,p.app);
    if(indexApp == (size_t)-1){
        // L'app n'existe pas 
        return 2;
    }
    JsonValue* entry_v = &apps_v->value.object->listeOfPair[indexApp].value;
    if(entry_v->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - entry value is not an object");
        return 1;
    }
    // L'ID existe ?
    size_t indexID = getIndexFromObjectWithKey(entry_v->value.object,p.id);
    if(indexID == (size_t)-1){
        // L'ID n'existe pas 
        return 3;
    }
    // On a les index pour recup l'entrie
    if(getEntry(entry_v->value.object->listeOfPair[indexID].value,e,p.show)){
        LOG_ERROR("Filling of an entry failed (getEntry)");
        return 1;
    }
    if(bt_strcpy(&e->app,p.app)){
        LOG_ERROR("Copy of a string failed (bt_strcpy)");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }
    if(bt_strcpy(&e->id,p.id)){
        LOG_ERROR("Copy of a string failed (bt_strcpy)");
        nukeString(e->pwd,bt_strlen(e->pwd));
        bt_deepFree(e->nbOfTags,(void**)e->tags);
        bt_multiFree(6,e->app,e->id,e->pwd,e->note,e->created,e->updated);
        *e = (CShildEntry){0};
        return 1;
    }

    return 0;
}

int getMatchingTags(JsonValue* vaultRoot,CShildEntry** e,size_t* numberOfEntry,CShildParams p){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL or not an object)");
        return 1;
    }
    if(e == NULL){
        LOG_ERROR("Corrupted pointer (e == NULL)");
        return 1;
    }
    if(numberOfEntry == NULL){
        LOG_ERROR("Corrupted pointer (numberOfEntry == NULL)");
        return 1;
    }
    if(p.tags == NULL){
        LOG_ERROR("Corrupted pointer (p.tags == NULL)");
        return 1;
    }
    if(p.nbOfTags == 0){
        LOG_ERROR("No tags provided");
        return 1;
    }

    *numberOfEntry = 0;
    *e = NULL;
    size_t indexor = 0;
    int state = 0;
    double versionCShild = getVersionCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    double versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    indexor = getIndexFromObjectWithKey(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
    }
    JsonValue* apps_v = &vaultRoot->value.object->listeOfPair[indexor].value;
    if(apps_v->type != JSON_OBJECT){
        LOG_ERROR("JSON of the vault altered - 'apps' value is not an object");
        return 1;
    }  

    
    for(size_t i=0;i<apps_v->value.object->nbOfElement;i++){
        JsonValue* IDs_p = &apps_v->value.object->listeOfPair[i].value;
        if(IDs_p->type != JSON_OBJECT){
            LOG_ERROR("JSON of the vault altered - IDs level value is not objects");
            for(size_t k=0;k<*numberOfEntry;k++){
                bt_freeCShildEntry(&(*e)[k]);
            }
            free(*e);
            *e = NULL;
            *numberOfEntry = 0;
            return 1;
        }
        char* appName_p = apps_v->value.object->listeOfPair[i].key;
        for(size_t j=0;j<IDs_p->value.object->nbOfElement;j++){
            JsonValue* Entries_p = &IDs_p->value.object->listeOfPair[j].value;
            if(Entries_p->type != JSON_OBJECT){
                LOG_ERROR("JSON of the vault altered - Entries level value is not objects");
                for(size_t k=0;k<*numberOfEntry;k++){
                    bt_freeCShildEntry(&(*e)[k]);
                }
                free(*e);
                *e = NULL;
                *numberOfEntry = 0;
                return 1;
            }
            char* idName_p = IDs_p->value.object->listeOfPair[j].key;
            CShildEntry buffer_e = {0};
            state = getEntry(*Entries_p,&buffer_e,p.show);
            if(state == 1){
                for(size_t k=0;k<*numberOfEntry;k++){
                    bt_freeCShildEntry(&(*e)[k]);
                }
                free(*e);
                *e = NULL;
                *numberOfEntry = 0;
                return 1;
            }
            state = isOneTagsMatching(buffer_e.tags,buffer_e.nbOfTags,p.tags,p.nbOfTags);
            if(state == 1){
                if(bt_strcpy(&buffer_e.app,appName_p) == 1){
                    LOG_ERROR("Copy of a string failed (bt_strcpy)");
                    bt_freeCShildEntry(&buffer_e);
                    for(size_t k=0;k<*numberOfEntry;k++){
                        bt_freeCShildEntry(&(*e)[k]);
                    }
                    free(*e);
                    *e = NULL;
                    *numberOfEntry = 0;
                    return 1;
                }

                if(bt_strcpy(&buffer_e.id,idName_p) == 1){
                    LOG_ERROR("Copy of a string failed (bt_strcpy)");
                    bt_freeCShildEntry(&buffer_e);
                    for(size_t k=0;k<*numberOfEntry;k++){
                        bt_freeCShildEntry(&(*e)[k]);
                    }
                    free(*e);
                    *e = NULL;
                    *numberOfEntry = 0;
                    return 1;
                }
                CShildEntry* buffer = realloc(*e,(*numberOfEntry + 1) * sizeof(CShildEntry));
                if(buffer == NULL){
                    LOG_ERROR("Error while allocating memory (buffer = realloc(*e,(*numberOfEntry + 1) * sizeof(CShildEntry)))");
                    bt_freeCShildEntry(&buffer_e);
                    for(size_t k=0;k<*numberOfEntry;k++){
                        bt_freeCShildEntry(&(*e)[k]);
                    }
                    free(*e);
                    *e = NULL;
                    *numberOfEntry = 0;
                    return 1;
                }
                
                *e = buffer;
                (*e)[*numberOfEntry] = buffer_e;
                (*numberOfEntry)++;
            }else{
                bt_freeCShildEntry(&buffer_e);
            }
        }
    }

    return 0;
}

//////////////////////////////

int getTime(char** dest){
    if (dest == NULL){
        LOG_ERROR("Corrupted pointer (dest == NULL)");
        return 1;
    }
    *dest = calloc(21, sizeof(char));
    if (*dest == NULL){
        LOG_ERROR("Error while allocating memory (*dest = calloc)");
        return 1;
    }
    time_t now = time(NULL);
    struct tm t;
    #ifdef _WIN32
        if (gmtime_s(&t, &now) != 0) { free(*dest); *dest = NULL; LOG_ERROR("Impossible to convert the time (gmtime_s)"); return 1; }
    #else
        if (gmtime_r(&now, &t) == NULL) { free(*dest); *dest = NULL; LOG_ERROR("Impossible to convert the time (gmtime_r)"); return 1; }
    #endif
    strftime(*dest, 21, "%Y-%m-%dT%H:%M:%SZ", &t);
    return 0;
}

size_t getTagIndex(JsonArray* ary,char* tag){
    if(ary == NULL || tag == NULL){
        return (size_t)-1;
    }

    for(size_t i = 0;i<ary->nbOfElement;i++){
        if(bt_strcmp(ary->listeOfValue[i].value.string,tag) == 0){
            return i;
        }
    }

    return (size_t)-1;
}


double getVersionVault(JsonValue vaultRoot){
    size_t indexVersion = getIndexFromObjectWithKey(vaultRoot.value.object,"version");
    if(indexVersion == (size_t) -1){
        LOG_ERROR("JSON of the vault altered - key 'version' not found");
        return -1;
    }
    return vaultRoot.value.object->listeOfPair[indexVersion].value.value.decimal;
}

int isOneTagsMatching(char** listeOfTags,size_t nbOfTags,char** listeOfSearchedTags,size_t nbOfSearchedTags){
    for(size_t i=0;i<nbOfTags;i++){
        for(size_t j=0;j<nbOfSearchedTags;j++){
            if(bt_strcmp(listeOfTags[i],listeOfSearchedTags[j]) == 0){
                return 1;
            }
        }
    }

    return 0;
}

static char* emptyString(void);
int getTime(char** dest);
void bt_multiFreeValue(size_t numberToFree, ...);

int generateNewBlankEntry(JsonObject* objDest){
    if(objDest == NULL){
        LOG_ERROR("Corrupted pointer (objDest == NULL)");
        return 1;
    }

    JsonValue password_v = initJsonValue(JSON_STRING);
    JsonValue note_v = initJsonValue(JSON_STRING);
    JsonValue tags_v = initJsonValue(JSON_ARRAY);
    if(newJsonArray(&tags_v)){
        LOG_ERROR("Creation of an array failed (newJsonArray)");
        return 1;
    }
    JsonValue password_history_v = initJsonValue(JSON_ARRAY);
    if(newJsonArray(&password_history_v)){
        LOG_ERROR("Creation of an array failed (newJsonArray)");
        freeValue(tags_v);
        return 1;
    }
    JsonValue created_at_v = initJsonValue(JSON_STRING);
    JsonValue updated_at_v = initJsonValue(JSON_STRING);

    password_v.value.string = emptyString();
    note_v.value.string = emptyString();
    if(password_v.value.string == NULL || note_v.value.string == NULL){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Error while allocating memory (emptyString)");
        return 1;
    }

    char* creationTime = NULL;
    if(getTime(&creationTime)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Impossible to fetch actual time (getTime)");
        return 1;
    }
    created_at_v.value.string = creationTime;

    char* updateTime = NULL;
    if(getTime(&updateTime)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Impossible to fetch actual time (getTime)");
        return 1;
    }
    updated_at_v.value.string = updateTime;


    if(addToObject(objDest,"password",password_v,0)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"note",note_v,1)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"tags",tags_v,2)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"password_history",password_history_v,3)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"created_at",created_at_v,4)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"updated_at",updated_at_v,5)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        return 1;
    }
    bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
    return 0;
}

int fillUpWithEntry(JsonObject* obj,CShildParams entry){
    if(obj == NULL){
        LOG_ERROR("Corrupted pointer (obj == NULL)");
        return 1;
    }

    int state = 0;
    if(entry.pwd != NULL){
        state = modPassword(obj,entry.pwd);
        if(state == 1){
            LOG_ERROR("Modification of password failed (modPassword)");
            return 1;
        }else if(state == 2){
            LOG_ERROR("Password empty recorded");
            return 2;
        }
    }

    if(entry.note != NULL){
        size_t indexNote = getIndexFromObjectWithKey(obj,"note");
        if(indexNote == (size_t)-1){
            LOG_ERROR("JSON altered or corrupted, key 'note' not found");
            return 1;
        }
        char* note = NULL;
        if(bt_strcpy(&note,entry.note)){
            LOG_ERROR("Copy of a string failed (bt_strcpy)");
            return 1;
        }
        freeValue(obj->listeOfPair[indexNote].value);
        obj->listeOfPair[indexNote].value.value.string = note;
    }

    if(entry.tags != NULL){
        size_t indexTags = getIndexFromObjectWithKey(obj,"tags");
        if(indexTags == (size_t)-1){
            LOG_ERROR("JSON altered or corrupted, key 'tags' not found");
            return 1;
        }

        JsonValue newArray = initJsonValue(JSON_ARRAY);
        if(newJsonArray(&newArray)){
            LOG_ERROR("Creation of an array failed (newJsonArray)");
            return 1;
        }
        for(size_t i=0;i< entry.nbOfTags;i++){
            JsonValue tag_v = initJsonValue(JSON_STRING);
            if(bt_strcpy(&tag_v.value.string,entry.tags[i])){
                freeValue(newArray);
                LOG_ERROR("Copy of a string failed (bt_strcpy)");
                return 1;
            }
            state = addToArray(newArray.value.array,tag_v,i);
            freeValue(tag_v);
            if(state){
                freeValue(newArray);
                LOG_ERROR("Adding a new value in an array failed (addToArray)");
                return 1;
            }
        }
        freeValue(obj->listeOfPair[indexTags].value);
        obj->listeOfPair[indexTags].value = newArray;
    }
    return 0;
}

static char* emptyString(void){
    return calloc(1,sizeof(char));
}

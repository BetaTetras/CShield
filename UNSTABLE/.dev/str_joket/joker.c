#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>

#include "../../include/common/bt_utils.h"

int bt_strii(char* str,char* part);
int jokerValidation(char* str,char* searchedFormat);

int main(){
    char* str_1 = "Hello World!";
    char* str_2 = "J'aime bien les pomme";
    char* str_3 = "La vie est belle";

    

    return 0;
}


// strii = is inside
int bt_strii(char* str,char* part){
    if(str == NULL || part == NULL){
        return -1;
    }
    size_t len_str = bt_strlen(str);
    size_t len_part = bt_strlen(part);
    if(len_str < len_part || len_part == 0 || len_str == 0){
        return 0;
    }

    size_t index = 0;
    size_t combo = 0;
    for(size_t i=0;i<len_str;i++){
        combo = 0;
        index = i;
        for(size_t j=0;j<len_part;j++){
            char str_c = str[index];
            char part_c = part[j];
            if(str_c >= 'a' && str_c <= 'z'){
                str_c = str_c - 32;
            }
            if(part_c >= 'a' && part_c <= 'z'){
                part_c = part_c - 32;
            }

            if(str_c == part_c){
                combo++;
                index++;
            }else{
                break;
            }

            if(combo == len_part){
                return 1;
            }
        }
    }
    return 0;
}
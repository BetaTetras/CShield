#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/ioctl.h>
    #include <unistd.h>
#endif

#include "bt_printf.h"
#include "bt_utils.h"
#include "bt_log.h"

#include "../AES-256-GCM/AES.h"
#include "../CSON/cson.h"

#ifdef _WIN32
    // Réglages d'origine de la console, pour les remettre à la fin du programme
    static UINT oldOutputCP = 0;
    static UINT oldInputCP = 0;
    static DWORD oldConsoleMode = 0;
    static int oldModeSaved = 0;

    static void restoreConsole(void){
        if(oldOutputCP != 0){
            SetConsoleOutputCP(oldOutputCP);
        }
        if(oldInputCP != 0){
            SetConsoleCP(oldInputCP);
        }
        if(oldModeSaved){
            SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE),oldConsoleMode);
        }
    }
#endif

// Prépare la console au tout premier affichage : UTF-8 et codes couleur ANSI. Sans effet hors Windows.
void initConsole(void){
    static int done = 0;
    if(done){
        return;
    }
    done = 1;
    #ifdef _WIN32
        oldOutputCP = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
        // Le clavier envoie du Windows-1252, que bt_fgetss convertit en UTF-8
        oldInputCP = GetConsoleCP();
        SetConsoleCP(1252);
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        if(GetConsoleMode(out,&oldConsoleMode)){
            oldModeSaved = 1;
            SetConsoleMode(out,oldConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        atexit(restoreConsole);
    #endif
}

void printf_RGB(int r, int g, int b, const char* format, ...) {
    initConsole();
    va_list args;
    va_start(args, format);
    printf("\033[38;2;%d;%d;%dm", r, g, b);
    vprintf(format, args);
    printf("\033[0m");
    va_end(args);
}

void printf_RGB_BG(int fr, int fg, int fb, int br, int bg, int bb, const char* format, ...) {
    initConsole();
    va_list args;
    va_start(args, format);
    printf("\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm", fr, fg, fb, br, bg, bb);
    vprintf(format, args);
    printf("\033[0m");
    va_end(args);
}

void char_RGB(int r, int g, int b, char c) {
    initConsole();
    printf("\033[38;2;%d;%d;%dm", r, g, b);
    printf("%c", c);
    printf("\033[0m");
}

static void printLevel(int r, int g, int b, const char* symbol, const char* label, const char* format, va_list args) BT_PRINTF_CHECK(6,0);

static void printLevel(int r, int g, int b, const char* symbol, const char* label, const char* format, va_list args){
    printf_RGB(r,g,b," %s  ",symbol);
    printf_RGB_BG(0,0,0,r,g,b," %s ",label);
    printf("\033[38;2;%d;%d;%dm ",r,g,b);
    vprintf(format,args);
    printf(" \n\033[0m");
}

void print_ERR(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(255,0,0,"✗","ERR",format,args);
    va_end(args);
}

void print_INF(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(127,0,255,"ℹ","INF",format,args);
    va_end(args);
}

void print_WRN(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(255,165,0,"⚑","WRN",format,args);
    va_end(args);
}

void print_SUC(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(0,255,0,"✓","SUC",format,args);
    va_end(args);
}

///////////////////////////// Boîtes d'affichage de shw (bt_boxSingleEntry, bt_boxMultiEntry, bt_boxTagsMatching, bt_boxWordMatching)

#define BOX_MAX_COLS      6
#define BOX_MIN_COL       6      // largeur en dessous de laquelle on ne réduit pas une colonne
#define BOX_DEFAULT_TERM  80
#define BOX_BULLETS       "••••••••"
#define BOX_BULLETS_COLS  8
#define BOX_HINT          "••••••••  (--show to reveal)"
#define BOX_HINT_COLS     28
#define BOX_LABEL_COLS    8      // "Password"
#define BOX_DATE_COLS     19     // "2026-09-18 14:02:11"

typedef struct {
    int r;
    int g;
    int b;
} BoxRgb;

// Cadre et titres (communs à toutes les boîtes)
static const BoxRgb BOX_FRAME    = {200,205,215};   // gris clair
static const BoxRgb BOX_TITLE    = {245,246,250};   // blanc
static const BoxRgb BOX_SUBTITLE = {170,176,190};
static const BoxRgb BOX_ID       = {200,206,220};

// Fiche : dégradé chaud de l'ambre au mauve, une teinte par ligne (la valeur est la même teinte, un peu plus sombre)
static const BoxRgb BOX_FICHE_LABEL[5] = {
    {255,190,100},   // Password : ambre
    {250,165,110},   // Tags : abricot
    {240,140,120},   // Note : corail
    {230,125,140},   // Created : rose
    {205,120,165}    // Updated : mauve
};

typedef enum {
    BOX_COL_APP,
    BOX_COL_ID,
    BOX_COL_PWD,
    BOX_COL_TAGS,
    BOX_COL_UPDATED,
    BOX_COL_MATCH
} BoxColKind;

typedef struct {
    BoxColKind kind;
    const char* header;
    size_t w;        // largeur du texte de la colonne (sans les marges)
    size_t minW;     // plus petite largeur possible (= w si la colonne ne peut pas être coupée)
    BoxRgb tint;
} BoxColumn;

typedef struct {
    const CShieldEntry* entries;
    size_t nbOfEntries;
    int show;
    char head[512];          // début du titre (gras)
    char tail[64];           // fin du titre : " · 3 entries"
    BoxColumn cols[BOX_MAX_COLS];
    size_t nbOfCols;
    BoxRgb gradStart;        // teinte de la première colonne
    BoxRgb gradEnd;          // teinte de la dernière colonne
} BoxTable;

///////////////////////////// Couleurs

static void boxFg(BoxRgb c,int bold){
    printf("\033[0%s;38;2;%d;%d;%dm",bold ? ";1" : "",c.r,c.g,c.b);
}

static void boxReset(void){
    fputs("\033[0m",stdout);
}

static int boxClamp(int v){
    if(v < 0){
        return 0;
    }
    if(v > 255){
        return 255;
    }
    return v;
}

static BoxRgb boxScale(BoxRgb c,int percent){
    return (BoxRgb){boxClamp(c.r * percent / 100),boxClamp(c.g * percent / 100),boxClamp(c.b * percent / 100)};
}

static BoxRgb boxLighten(BoxRgb c,int add){
    return (BoxRgb){boxClamp(c.r + add),boxClamp(c.g + add),boxClamp(c.b + add)};
}

// Teinte numéro i sur n, du dégradé a -> b
static BoxRgb boxMix(BoxRgb a,BoxRgb b,size_t i,size_t n){
    if(n <= 1){
        return a;
    }
    int steps = (int)(n - 1);
    int k = (int)i;
    return (BoxRgb){a.r + (b.r - a.r) * k / steps,a.g + (b.g - a.g) * k / steps,a.b + (b.b - a.b) * k / steps};
}

///////////////////////////// Terminal

// Nombre de colonnes utilisables : celles du terminal moins une (une ligne pleine fait sauter une ligne sur certains terminaux).
static size_t boxMaxWidth(void){
    size_t cols = 0;
    #ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO info;
        if(GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&info)){
            int w = info.srWindow.Right - info.srWindow.Left + 1;
            if(w > 0){
                cols = (size_t)w;
            }
        }
    #else
        struct winsize ws;
        if(ioctl(STDOUT_FILENO,TIOCGWINSZ,&ws) == 0 && ws.ws_col > 0){
            cols = ws.ws_col;
        }
    #endif
    if(cols == 0){
        const char* env = getenv("COLUMNS");
        if(env != NULL){
            long v = strtol(env,NULL,10);
            if(v > 0 && v < 1000){
                cols = (size_t)v;
            }
        }
    }
    if(cols == 0){
        cols = BOX_DEFAULT_TERM;
    }
    if(cols < 21){
        cols = 21;
    }
    return cols - 1;
}

///////////////////////////// Texte UTF-8

// Octets du caractère UTF-8 qui commence en s (1 si la séquence est invalide).
// *blank vaut 1 si ce caractère doit s'afficher comme un espace : contrôle ASCII, contrôle C1 ou séquence invalide.
static size_t boxCharLen(const char* s,int* blank){
    unsigned char c = (unsigned char)s[0];
    *blank = 0;
    if(c < 0x20 || c == 0x7F){
        *blank = 1;
        return 1;
    }
    if(c < 0x80){
        return 1;
    }
    size_t n = 0;
    if((c & 0xE0) == 0xC0){
        n = 2;
    }else if((c & 0xF0) == 0xE0){
        n = 3;
    }else if((c & 0xF8) == 0xF0){
        n = 4;
    }else{
        *blank = 1;
        return 1;
    }
    for(size_t k=1;k<n;k++){
        if(((unsigned char)s[k] & 0xC0) != 0x80){
            *blank = 1;
            return 1;
        }
    }
    if(n == 2 && c == 0xC2 && (unsigned char)s[1] < 0xA0){
        *blank = 1;
    }
    return n;
}

// Largeur affichée : une colonne par caractère.
static size_t boxCols(const char* s){
    if(s == NULL){
        return 0;
    }
    size_t n = 0;
    while(*s != '\0'){
        int blank;
        s += boxCharLen(s,&blank);
        n++;
    }
    return n;
}

// Pointeur après les n premiers caractères de s (ou la fin de s)
static const char* boxSkipChars(const char* s,size_t n){
    while(n > 0 && *s != '\0'){
        int blank;
        s += boxCharLen(s,&blank);
        n--;
    }
    return s;
}

static void boxPutSpaces(size_t n){
    for(size_t i=0;i<n;i++){
        fputc(' ',stdout);
    }
}

static void boxPutRepeat(const char* s,size_t n){
    for(size_t i=0;i<n;i++){
        fputs(s,stdout);
    }
}

// Écrit les caractères de [s,end), les contrôles remplacés par des espaces.
static void boxPutRange(const char* s,const char* end){
    while(s < end){
        int blank;
        size_t n = boxCharLen(s,&blank);
        if(blank){
            fputc(' ',stdout);
        }else{
            fwrite(s,1,n,stdout);
        }
        s += n;
    }
}

// Écrit au plus maxCols caractères de s. Renvoie le nombre de colonnes écrites.
static size_t boxPutClip(const char* s,size_t maxCols){
    size_t cols = 0;
    if(s == NULL){
        return 0;
    }
    while(*s != '\0' && cols < maxCols){
        int blank;
        size_t n = boxCharLen(s,&blank);
        if(blank){
            fputc(' ',stdout);
        }else{
            fwrite(s,1,n,stdout);
        }
        s += n;
        cols++;
    }
    return cols;
}

// Écrit s dans exactement w colonnes : coupé avec « … » s'il est trop long, complété d'espaces sinon.
static void boxPutCell(const char* s,size_t w){
    size_t used = 0;
    if(boxCols(s) <= w){
        used = boxPutClip(s,w);
    }else if(w > 0){
        used = boxPutClip(s,w - 1);
        fputs("…",stdout);
        used++;
    }
    boxPutSpaces(w - used);
}

// Séparateur d'espacement du texte libre : l'espace, les contrôles ASCII (mais pas la fin de chaîne)
static int boxIsSep(char c){
    unsigned char u = (unsigned char)c;
    return u != 0 && (u == ' ' || u < 0x20 || u == 0x7F);
}

// Écrit les mots de [p,end) séparés par un seul espace (largeur = mots + espaces simples).
static void boxPutWords(const char* p,const char* end){
    int first = 1;
    while(p < end){
        while(p < end && boxIsSep(*p)){
            p++;
        }
        if(p >= end){
            break;
        }
        const char* e = p;
        while(e < end && !boxIsSep(*e)){
            int blank;
            e += boxCharLen(e,&blank);
        }
        if(!first){
            fputc(' ',stdout);
        }
        boxPutRange(p,e);
        first = 0;
        p = e;
    }
}

// "2026-09-18T14:02:11Z" -> "2026-09-18 14:02:11" (withTime) ou "2026-09-18". out : 20 octets au moins.
static void boxFormatDate(const char* iso,int withTime,char* out,size_t outSize){
    size_t want = withTime ? 19 : 10;
    size_t i = 0;
    if(iso != NULL){
        for(;i<want && iso[i] != '\0' && i + 1 < outSize;i++){
            out[i] = (iso[i] == 'T') ? ' ' : iso[i];
        }
    }
    out[i] = '\0';
    if(i == 0 && outSize > 1){
        out[0] = '-';
        out[1] = '\0';
    }
}

///////////////////////////// Fiche (une entrée)

// Début d'une ligne de la fiche : "│ label │ "
static void boxFicheStart(const char* label,BoxRgb labelColor){
    boxFg(BOX_FRAME,0);
    fputs("│ ",stdout);
    boxFg(labelColor,0);
    printf("%-*s",BOX_LABEL_COLS,label);
    boxFg(BOX_FRAME,0);
    fputs(" │ ",stdout);
}

// Fin d'une ligne de la fiche (la valeur a déjà été complétée d'espaces jusqu'à valueW)
static void boxFicheEnd(void){
    boxFg(BOX_FRAME,0);
    fputs(" │",stdout);
    boxReset();
    fputc('\n',stdout);
}

static void boxFicheRule(const char* left,const char* mid,const char* right,size_t valueW){
    boxFg(BOX_FRAME,0);
    fputs(left,stdout);
    boxPutRepeat("─",BOX_LABEL_COLS + 2);
    fputs(mid,stdout);
    boxPutRepeat("─",valueW + 2);
    fputs(right,stdout);
    boxReset();
    fputc('\n',stdout);
}

int bt_boxSingleEntry(const CShieldEntry* entry,int show){
    if(entry == NULL){
        LOG_ERROR("Corrupted pointer (entry == NULL)");
        return 1;
    }
    initConsole();
    show = (show != 0);

    BoxRgb label[5];
    BoxRgb value[5];
    for(size_t i=0;i<5;i++){
        label[i] = BOX_FICHE_LABEL[i];
        value[i] = boxScale(BOX_FICHE_LABEL[i],86);
    }

    // Largeur de la colonne des valeurs : le plus large entre dates, mot de passe et titre, sans dépasser le terminal.
    // Les tags et la note ne comptent pas : ils passent à la ligne.
    size_t appW = boxCols(entry->app);
    size_t idW = boxCols(entry->id);
    size_t valueW = BOX_DATE_COLS;
    size_t need = show ? boxCols(entry->pwd) : BOX_HINT_COLS;
    if(need > valueW){
        valueW = need;
    }
    need = appW + 3 + idW;                 // "app › id" tient dans valueW + 11 colonnes
    if(need > 11 && need - 11 > valueW){
        valueW = need - 11;
    }
    size_t maxW = boxMaxWidth();
    size_t capW = (maxW > 15 + BOX_DATE_COLS) ? maxW - 15 : BOX_DATE_COLS;
    if(valueW > capW){
        valueW = capW;
    }

    // Haut + titre
    boxFg(BOX_FRAME,0);
    fputs("┌",stdout);
    boxPutRepeat("─",valueW + 13);
    fputs("┐",stdout);
    boxReset();
    fputc('\n',stdout);

    size_t avail = valueW + 11;
    size_t limit = (appW + 3 + idW <= avail) ? avail : avail - 1;
    size_t used = 0;
    boxFg(BOX_FRAME,0);
    fputs("│ ",stdout);
    boxFg(BOX_TITLE,1);
    used += boxPutClip(entry->app,limit - used);
    boxFg(BOX_FRAME,0);
    used += boxPutClip(" › ",limit - used);
    boxFg(BOX_ID,1);
    used += boxPutClip(entry->id,limit - used);
    if(appW + 3 + idW > avail){
        fputs("…",stdout);
        used++;
    }
    boxPutSpaces(avail - used);
    boxFicheEnd();
    boxFicheRule("├","┬","┤",valueW);

    // Password : masqué, ou en clair coupé net toutes les valueW colonnes (jamais tronqué)
    if(show){
        const char* p = (entry->pwd != NULL) ? entry->pwd : "";
        int firstLine = 1;
        do{
            boxFicheStart(firstLine ? "Password" : "",label[0]);
            boxFg(value[0],0);
            size_t n = boxPutClip(p,valueW);
            p = boxSkipChars(p,n);
            boxPutSpaces(valueW - n);
            boxFicheEnd();
            firstLine = 0;
        }while(*p != '\0');
    }else{
        boxFicheStart("Password",label[0]);
        boxFg(value[0],0);
        boxPutCell((valueW >= BOX_HINT_COLS) ? BOX_HINT : BOX_BULLETS,valueW);
        boxFicheEnd();
    }

    // Tags : séparés par ", ", à la ligne dès que le suivant ne tient plus (virgule en fin de ligne).
    // Un tag plus large que la colonne est coupé et sa suite passe à la ligne suivante.
    if(entry->tags == NULL || entry->nbOfTags == 0){
        boxFicheStart("Tags",label[1]);
        boxFg(value[1],0);
        boxPutCell("-",valueW);
        boxFicheEnd();
    }else{
        size_t nbLines = 0;
        size_t t = 0;                                  // tag en cours
        const char* rest = entry->tags[0];             // partie du tag pas encore affichée
        do{
            boxFicheStart(nbLines == 0 ? "Tags" : "",label[1]);
            boxFg(value[1],0);
            size_t w = 0;
            int cut = 0;
            while(t < entry->nbOfTags){
                size_t tagW = boxCols(rest);
                size_t reserve = (t + 1 < entry->nbOfTags) ? 1 : 0;     // place pour la virgule si un tag suit
                size_t sep = (w == 0) ? 0 : 2;
                if(w + sep + tagW + reserve > valueW){
                    if(w != 0){
                        break;                                          // ne tient pas : ligne suivante
                    }
                    w += boxPutClip(rest,valueW - reserve);             // seul sur sa ligne et trop large : on le coupe
                    rest = boxSkipChars(rest,valueW - reserve);
                    cut = 1;
                    break;
                }
                if(w != 0){
                    fputs(", ",stdout);
                }
                boxPutClip(rest,tagW);
                w += sep + tagW;
                t++;
                rest = (t < entry->nbOfTags) ? entry->tags[t] : "";
            }
            if(t < entry->nbOfTags && !cut){
                fputc(',',stdout);
                w++;
            }
            boxPutSpaces(valueW - w);
            boxFicheEnd();
            nbLines++;
        }while(t < entry->nbOfTags);
    }

    // Note : coupée aux espaces pour tenir dans valueW colonnes (un mot trop long est coupé net)
    const char* p = (entry->note != NULL) ? entry->note : "";
    size_t nbLines = 0;
    for(;;){
        while(boxIsSep(*p)){
            p++;
        }
        if(*p == '\0'){
            break;
        }
        const char* end = p;     // fin (exclue) du texte de cette ligne
        size_t w = 0;            // largeur affichée de p..end
        const char* q = p;       // début du mot en cours
        while(*q != '\0'){
            const char* e = q;
            size_t ww = 0;
            while(*e != '\0' && !boxIsSep(*e)){
                int blank;
                e += boxCharLen(e,&blank);
                ww++;
            }
            if(end == p && ww > valueW){
                e = boxSkipChars(q,valueW);                             // premier mot trop large : coupé à valueW colonnes
                ww = valueW;
            }
            size_t needed = (end == p) ? ww : w + 1 + ww;
            if(needed > valueW){
                break;
            }
            w = needed;
            end = e;
            q = e;
            while(boxIsSep(*q)){
                q++;
            }
        }
        boxFicheStart(nbLines == 0 ? "Note" : "",label[2]);
        boxFg(value[2],0);
        boxPutWords(p,end);
        boxPutSpaces(valueW - w);
        boxFicheEnd();
        nbLines++;
        p = end;
    }
    if(nbLines == 0){
        boxFicheStart("Note",label[2]);
        boxFg(value[2],0);
        boxPutCell("-",valueW);
        boxFicheEnd();
    }

    // Dates + bas
    char date[24];
    boxFormatDate(entry->created,1,date,sizeof(date));
    boxFicheStart("Created",label[3]);
    boxFg(value[3],0);
    boxPutCell(date,valueW);
    boxFicheEnd();
    boxFormatDate(entry->updated,1,date,sizeof(date));
    boxFicheStart("Updated",label[4]);
    boxFg(value[4],0);
    boxPutCell(date,valueW);
    boxFicheEnd();
    boxFicheRule("└","┴","┘",valueW);
    return 0;
}

///////////////////////////// Tableaux (plusieurs entrées)

static void boxAddColumn(BoxTable* t,BoxColKind kind,const char* header){
    BoxColumn* c = &t->cols[t->nbOfCols];
    t->nbOfCols++;
    c->kind = kind;
    c->header = header;
    c->w = 0;
    c->minW = 0;
}

static size_t boxTagsCols(const CShieldEntry* e){
    if(e->tags == NULL || e->nbOfTags == 0){
        return 1;                                       // "-"
    }
    size_t w = 2 * (e->nbOfTags - 1);
    for(size_t i=0;i<e->nbOfTags;i++){
        w += boxCols(e->tags[i]);
    }
    return w;
}

// Largeur du texte de la cellule (colonne c, entrée e)
static size_t boxCellCols(const BoxTable* t,const BoxColumn* c,const CShieldEntry* e){
    switch(c->kind){
        case BOX_COL_APP:
            return boxCols(e->app);
        case BOX_COL_ID:
            return boxCols(e->id);
        case BOX_COL_PWD:
            return t->show ? boxCols(e->pwd) : BOX_BULLETS_COLS;
        case BOX_COL_TAGS:
            return boxTagsCols(e);
        case BOX_COL_UPDATED:
            return 10;
        case BOX_COL_MATCH:
            return (e->matchingSrc != NULL && e->matchingSrc[0] != '\0') ? boxCols(e->matchingSrc) : 1;
    }
    return 0;
}

// Largeur naturelle de chaque colonne : la plus large de son en-tête et de ses cellules
static void boxMeasure(BoxTable* t){
    for(size_t k=0;k<t->nbOfCols;k++){
        BoxColumn* c = &t->cols[k];
        size_t headerW = boxCols(c->header);
        size_t w = headerW;
        for(size_t i=0;i<t->nbOfEntries;i++){
            size_t cw = boxCellCols(t,c,&t->entries[i]);
            if(cw > w){
                w = cw;
            }
        }
        c->w = w;
        int shrinkable = (c->kind == BOX_COL_APP || c->kind == BOX_COL_ID || c->kind == BOX_COL_TAGS || c->kind == BOX_COL_MATCH);
        size_t floorW = (headerW > BOX_MIN_COL) ? headerW : BOX_MIN_COL;
        c->minW = (shrinkable && floorW < w) ? floorW : w;
    }
}

// Largeur totale du tableau : texte + 2 marges par colonne + les barres verticales
static size_t boxTableWidth(const BoxTable* t){
    size_t total = t->nbOfCols + 1;
    for(size_t k=0;k<t->nbOfCols;k++){
        total += t->cols[k].w + 2;
    }
    return total;
}

// Réduit, un caractère à la fois, la colonne coupable la plus large. Renvoie 1 si le tableau tient dans maxW.
static int boxShrinkToFit(BoxTable* t,size_t maxW){
    while(boxTableWidth(t) > maxW){
        size_t best = t->nbOfCols;
        for(size_t k=0;k<t->nbOfCols;k++){
            if(t->cols[k].w > t->cols[k].minW && (best == t->nbOfCols || t->cols[k].w > t->cols[best].w)){
                best = k;
            }
        }
        if(best == t->nbOfCols){
            return 0;
        }
        t->cols[best].w--;
    }
    return 1;
}

static int boxDropPasswordColumn(BoxTable* t){
    for(size_t k=0;k<t->nbOfCols;k++){
        if(t->cols[k].kind == BOX_COL_PWD){
            for(size_t j=k;j+1<t->nbOfCols;j++){
                t->cols[j] = t->cols[j + 1];
            }
            t->nbOfCols--;
            return 1;
        }
    }
    return 0;
}

// Écrit les tags d'une entrée dans w colonnes, tous de la même teinte.
static void boxPutTagsCell(const CShieldEntry* e,size_t w,BoxRgb color){
    boxFg(color,0);
    if(e->tags == NULL || e->nbOfTags == 0){
        boxPutCell("-",w);
        return;
    }
    size_t total = boxTagsCols(e);
    size_t limit = (total <= w) ? w : ((w > 0) ? w - 1 : 0);
    size_t used = 0;
    for(size_t i=0;i<e->nbOfTags && used < limit;i++){
        if(i > 0){
            used += boxPutClip(", ",limit - used);
            if(used >= limit){
                break;
            }
        }
        used += boxPutClip(e->tags[i],limit - used);
    }
    if(total > w && w > 0){
        fputs("…",stdout);
        used++;
    }
    boxPutSpaces(w - used);
}

static void boxPutRowCell(const BoxTable* t,const BoxColumn* c,const CShieldEntry* e,size_t row){
    // une ligne sur deux légèrement plus sombre
    BoxRgb color = (row % 2 == 1) ? boxScale(c->tint,84) : c->tint;
    char date[24];
    switch(c->kind){
        case BOX_COL_APP:
            boxFg(color,0);
            boxPutCell(e->app,c->w);
            break;
        case BOX_COL_ID:
            boxFg(color,0);
            boxPutCell(e->id,c->w);
            break;
        case BOX_COL_PWD:
            boxFg(color,0);
            boxPutCell(t->show ? e->pwd : BOX_BULLETS,c->w);
            break;
        case BOX_COL_TAGS:
            boxPutTagsCell(e,c->w,color);
            break;
        case BOX_COL_UPDATED:
            boxFormatDate(e->updated,0,date,sizeof(date));
            boxFg(color,0);
            boxPutCell(date,c->w);
            break;
        case BOX_COL_MATCH:
            boxFg(color,0);
            boxPutCell((e->matchingSrc != NULL && e->matchingSrc[0] != '\0') ? e->matchingSrc : "-",c->w);
            break;
    }
}

// Ligne horizontale avec les jonctions des colonnes : ├──┬──┤, ├──┼──┤ ou └──┴──┘
static void boxTableRule(const BoxTable* t,const char* left,const char* mid,const char* right){
    boxFg(BOX_FRAME,0);
    fputs(left,stdout);
    for(size_t k=0;k<t->nbOfCols;k++){
        boxPutRepeat("─",t->cols[k].w + 2);
        fputs((k + 1 < t->nbOfCols) ? mid : right,stdout);
    }
    boxReset();
    fputc('\n',stdout);
}

static void boxPrintTable(BoxTable* t){
    boxMeasure(t);
    size_t maxW = boxMaxWidth();
    if(!boxShrinkToFit(t,maxW) && !t->show){
        // Toujours trop large : sans mot de passe en clair, la colonne Password ne sert à rien, on la retire
        if(boxDropPasswordColumn(t)){
            boxShrinkToFit(t,maxW);
        }
    }

    // Titre plus large que le tableau : on élargit la dernière colonne s'il reste de la place
    size_t titleCols = boxCols(t->head) + boxCols(t->tail);
    size_t avail = boxTableWidth(t) - 4;
    if(titleCols > avail && boxTableWidth(t) + (titleCols - avail) <= maxW){
        t->cols[t->nbOfCols - 1].w += titleCols - avail;
        avail = titleCols;
    }

    // Dégradé réparti sur les colonnes restantes
    for(size_t k=0;k<t->nbOfCols;k++){
        t->cols[k].tint = boxMix(t->gradStart,t->gradEnd,k,t->nbOfCols);
    }

    // Haut
    size_t total = boxTableWidth(t);
    boxFg(BOX_FRAME,0);
    fputs("┌",stdout);
    boxPutRepeat("─",total - 2);
    fputs("┐",stdout);
    boxReset();
    fputc('\n',stdout);

    // Titre : début en gras, fin (nombre d'entrées) plus discrète
    size_t limit = (titleCols <= avail) ? avail : avail - 1;
    size_t used = 0;
    boxFg(BOX_FRAME,0);
    fputs("│ ",stdout);
    boxFg(BOX_TITLE,1);
    used += boxPutClip(t->head,limit - used);
    boxFg(BOX_SUBTITLE,0);
    used += boxPutClip(t->tail,limit - used);
    if(titleCols > avail){
        fputs("…",stdout);
        used++;
    }
    boxPutSpaces(avail - used);
    boxFg(BOX_FRAME,0);
    fputs(" │",stdout);
    boxReset();
    fputc('\n',stdout);
    boxTableRule(t,"├","┬","┤");

    // En-têtes
    boxFg(BOX_FRAME,0);
    fputs("│",stdout);
    for(size_t k=0;k<t->nbOfCols;k++){
        fputc(' ',stdout);
        boxFg(boxLighten(t->cols[k].tint,40),1);
        boxPutCell(t->cols[k].header,t->cols[k].w);
        fputc(' ',stdout);
        boxFg(BOX_FRAME,0);
        fputs("│",stdout);
    }
    boxReset();
    fputc('\n',stdout);
    boxTableRule(t,"├","┼","┤");

    // Lignes
    for(size_t i=0;i<t->nbOfEntries;i++){
        boxFg(BOX_FRAME,0);
        fputs("│",stdout);
        for(size_t k=0;k<t->nbOfCols;k++){
            fputc(' ',stdout);
            boxPutRowCell(t,&t->cols[k],&t->entries[i],i);
            fputc(' ',stdout);
            boxFg(BOX_FRAME,0);
            fputs("│",stdout);
        }
        boxReset();
        fputc('\n',stdout);
    }
    boxTableRule(t,"└","┴","┘");
}

// " · 3 entries" / " · 1 entry"
static void boxSetCount(BoxTable* t){
    snprintf(t->tail,sizeof(t->tail)," · %llu %s",(unsigned long long)t->nbOfEntries,(t->nbOfEntries == 1) ? "entry" : "entries");
}

// prefix + termes séparés par " AND " ou " OR " ("Tags: gaming AND perso")
static void boxJoinTerms(char* out,size_t outSize,const char* prefix,char** terms,size_t n,char op){
    int r = snprintf(out,outSize,"%s",prefix);
    size_t len = (r < 0) ? 0 : (size_t)r;
    for(size_t i=0;i<n;i++){
        if(len >= outSize){
            break;
        }
        const char* sep = (i == 0) ? "" : ((op == '&') ? " AND " : " OR ");
        r = snprintf(out + len,outSize - len,"%s%s",sep,(terms[i] != NULL) ? terms[i] : "");
        if(r < 0){
            break;
        }
        len += (size_t)r;
    }
}

int bt_boxMultiEntry(const CShieldEntry* entries,size_t nbOfEntries,int show){
    if(entries == NULL && nbOfEntries > 0){
        LOG_ERROR("Corrupted pointer (entries == NULL)");
        return 1;
    }
    initConsole();
    if(nbOfEntries == 0){
        print_INF("No entry");
        return 0;
    }

    BoxTable t = {0};
    t.entries = entries;
    t.nbOfEntries = nbOfEntries;
    t.show = (show != 0);
    boxAddColumn(&t,BOX_COL_ID,"ID");
    boxAddColumn(&t,BOX_COL_PWD,"Password");
    boxAddColumn(&t,BOX_COL_TAGS,"Tags");
    boxAddColumn(&t,BOX_COL_UPDATED,"Updated");
    snprintf(t.head,sizeof(t.head),"%s",(entries[0].app != NULL) ? entries[0].app : "");
    boxSetCount(&t);
    t.gradStart = (BoxRgb){100,215,215};     // turquoise
    t.gradEnd = (BoxRgb){150,130,240};       // indigo
    boxPrintTable(&t);
    return 0;
}

int bt_boxTagsMatching(const CShieldEntry* entries,size_t nbOfEntries,int show,char** tags,size_t nbOfTags,char logicalOperator){
    if((entries == NULL && nbOfEntries > 0) || tags == NULL || nbOfTags == 0){
        LOG_ERROR("Corrupted pointer or no tag (entries == NULL, tags == NULL or nbOfTags == 0)");
        return 1;
    }
    initConsole();

    BoxTable t = {0};
    boxJoinTerms(t.head,sizeof(t.head),"Tags: ",tags,nbOfTags,logicalOperator);
    if(nbOfEntries == 0){
        boxJoinTerms(t.head,sizeof(t.head),"",tags,nbOfTags,logicalOperator);
        print_INF("No match for tags \"%s\"",t.head);
        return 0;
    }
    t.entries = entries;
    t.nbOfEntries = nbOfEntries;
    t.show = (show != 0);
    boxAddColumn(&t,BOX_COL_APP,"App");
    boxAddColumn(&t,BOX_COL_ID,"ID");
    boxAddColumn(&t,BOX_COL_PWD,"Password");
    boxAddColumn(&t,BOX_COL_TAGS,"Tags");
    boxAddColumn(&t,BOX_COL_UPDATED,"Updated");
    boxSetCount(&t);
    t.gradStart = (BoxRgb){110,225,150};     // menthe
    t.gradEnd = (BoxRgb){215,230,110};       // citron
    boxPrintTable(&t);
    return 0;
}

int bt_boxWordMatching(const CShieldEntry* entries,size_t nbOfEntries,int show,char** words,size_t nbOfWords,char logicalOperator){
    if((entries == NULL && nbOfEntries > 0) || words == NULL || nbOfWords == 0){
        LOG_ERROR("Corrupted pointer or no word (entries == NULL, words == NULL or nbOfWords == 0)");
        return 1;
    }
    initConsole();

    BoxTable t = {0};
    boxJoinTerms(t.head,sizeof(t.head),"Search: ",words,nbOfWords,logicalOperator);
    if(nbOfEntries == 0){
        boxJoinTerms(t.head,sizeof(t.head),"",words,nbOfWords,logicalOperator);
        print_INF("No match for \"%s\"",t.head);
        return 0;
    }
    t.entries = entries;
    t.nbOfEntries = nbOfEntries;
    t.show = (show != 0);
    boxAddColumn(&t,BOX_COL_APP,"App");
    boxAddColumn(&t,BOX_COL_ID,"ID");
    boxAddColumn(&t,BOX_COL_PWD,"Password");
    boxAddColumn(&t,BOX_COL_TAGS,"Tags");
    boxAddColumn(&t,BOX_COL_UPDATED,"Updated");
    boxAddColumn(&t,BOX_COL_MATCH,"Match");
    boxSetCount(&t);
    t.gradStart = (BoxRgb){170,140,255};     // violet
    t.gradEnd = (BoxRgb){240,125,200};       // magenta
    boxPrintTable(&t);
    return 0;
}

///////////////////////////// Liste des vaults (CShield vaults)

#define BOX_VAULT_BAR_COLS  20     // largeur voulue de la barre de comparaison
#define BOX_VAULT_BAR_MIN   4
#define BOX_VAULT_NAME_MIN  6

// 512 -> "512 B", 1536 -> "1.5 KB", 3145728 -> "3.0 MB"
static void boxFormatSize(size_t bytes,char* out,size_t outSize){
    const char* units[] = {"B","KB","MB","GB"};
    double v = (double)bytes;
    size_t u = 0;
    while(v >= 1023.95 && u < 3){
        v /= 1024.0;
        u++;
    }
    if(u == 0){
        snprintf(out,outSize,"%llu B",(unsigned long long)bytes);
    }else{
        snprintf(out,outSize,"%.1f %s",v,units[u]);
    }
}

// Texte aligné à droite dans w colonnes (w >= largeur du texte)
static void boxPutRight(const char* s,size_t w){
    boxPutSpaces(w - boxCols(s));
    fputs(s,stdout);
}

// Barre de w cases remplie à eighths/8 de case : cases pleines (█), une case partielle (▏ à ▉), le reste en plus sombre (░)
static void boxPutBar(size_t eighths,size_t w,BoxRgb color){
    const char* partial[] = {"▏","▎","▍","▌","▋","▊","▉"};
    size_t full = eighths / 8;
    size_t rest = eighths % 8;
    boxFg(color,0);
    boxPutRepeat("█",full);
    if(rest > 0){
        fputs(partial[rest - 1],stdout);
    }
    boxFg(boxScale(color,40),0);
    boxPutRepeat("░",w - full - ((rest > 0) ? 1 : 0));
}

int bt_boxVaults(char** names,const size_t* sizes,size_t nbOfVaults){
    if((names == NULL || sizes == NULL) && nbOfVaults > 0){
        LOG_ERROR("Corrupted pointer (names == NULL or sizes == NULL)");
        return 1;
    }
    initConsole();
    if(nbOfVaults == 0){
        print_INF("No vault");
        return 0;
    }

    // Mesures : nom le plus large, taille la plus large, plus gros vault (= barre pleine) et total
    char text[32];
    size_t nameW = boxCols("Vault");
    size_t sizeW = boxCols("Size");
    size_t biggest = 0;
    size_t total = 0;
    for(size_t i=0;i<nbOfVaults;i++){
        size_t w = boxCols(names[i]);
        if(w > nameW){
            nameW = w;
        }
        boxFormatSize(sizes[i],text,sizeof(text));
        w = boxCols(text);
        if(w > sizeW){
            sizeW = w;
        }
        if(sizes[i] > biggest){
            biggest = sizes[i];
        }
        total += sizes[i];
    }

    // Largeur totale = largeurs + 2 marges par colonne + les barres verticales (10 avec 3 colonnes, 7 avec 2)
    size_t barW = BOX_VAULT_BAR_COLS;
    size_t maxW = boxMaxWidth();
    while(nameW + sizeW + barW + 10 > maxW){
        if(nameW > BOX_VAULT_NAME_MIN && nameW >= barW){
            nameW--;
        }else if(barW > BOX_VAULT_BAR_MIN){
            barW--;
        }else if(nameW > BOX_VAULT_NAME_MIN){
            nameW--;
        }else{
            break;
        }
    }
    size_t nbCols = 3;
    if(nameW + sizeW + barW + 10 > maxW){
        // Toujours trop large : on retire la barre et on garde Vault et Size
        nbCols = 2;
        while(nameW + sizeW + 7 > maxW && nameW > 3){
            nameW--;
        }
    }

    BoxTable t = {0};
    t.nbOfCols = nbCols;
    t.cols[0].header = "Vault";
    t.cols[0].w = nameW;
    t.cols[1].header = "Size";
    t.cols[1].w = sizeW;
    t.cols[2].header = "Compare";
    t.cols[2].w = barW;
    BoxRgb gradStart = {250,135,125};        // corail
    BoxRgb gradEnd = {235,200,105};          // or
    for(size_t k=0;k<nbCols;k++){
        t.cols[k].tint = boxMix(gradStart,gradEnd,k,nbCols);
    }

    // Titre plus large que le tableau : on élargit la dernière colonne s'il reste de la place
    char head[] = "Vaults";
    char tail[96];
    boxFormatSize(total,text,sizeof(text));
    snprintf(tail,sizeof(tail)," · %llu %s · %s",(unsigned long long)nbOfVaults,(nbOfVaults == 1) ? "vault" : "vaults",text);
    size_t titleCols = boxCols(head) + boxCols(tail);
    size_t avail = boxTableWidth(&t) - 4;
    if(titleCols > avail && boxTableWidth(&t) + (titleCols - avail) <= maxW){
        t.cols[nbCols - 1].w += titleCols - avail;
        avail = titleCols;
    }

    // Haut
    boxFg(BOX_FRAME,0);
    fputs("┌",stdout);
    boxPutRepeat("─",boxTableWidth(&t) - 2);
    fputs("┐",stdout);
    boxReset();
    fputc('\n',stdout);

    // Titre : « Vaults » en gras, le reste (nombre et poids total) plus discret
    size_t limit = (titleCols <= avail) ? avail : avail - 1;
    size_t used = 0;
    boxFg(BOX_FRAME,0);
    fputs("│ ",stdout);
    boxFg(BOX_TITLE,1);
    used += boxPutClip(head,limit - used);
    boxFg(BOX_SUBTITLE,0);
    used += boxPutClip(tail,limit - used);
    if(titleCols > avail){
        fputs("…",stdout);
        used++;
    }
    boxPutSpaces(avail - used);
    boxFg(BOX_FRAME,0);
    fputs(" │",stdout);
    boxReset();
    fputc('\n',stdout);
    boxTableRule(&t,"├","┬","┤");

    // En-têtes (Size aligné à droite comme ses valeurs)
    boxFg(BOX_FRAME,0);
    fputs("│",stdout);
    for(size_t k=0;k<nbCols;k++){
        fputc(' ',stdout);
        boxFg(boxLighten(t.cols[k].tint,40),1);
        if(k == 1){
            boxPutRight(t.cols[k].header,t.cols[k].w);
        }else{
            boxPutCell(t.cols[k].header,t.cols[k].w);
        }
        fputc(' ',stdout);
        boxFg(BOX_FRAME,0);
        fputs("│",stdout);
    }
    boxReset();
    fputc('\n',stdout);
    boxTableRule(&t,"├","┼","┤");

    // Lignes : une sur deux légèrement plus sombre. La barre est proportionnelle au plus gros vault.
    for(size_t i=0;i<nbOfVaults;i++){
        BoxRgb tint[3];
        for(size_t k=0;k<nbCols;k++){
            tint[k] = (i % 2 == 1) ? boxScale(t.cols[k].tint,84) : t.cols[k].tint;
        }
        boxFg(BOX_FRAME,0);
        fputs("│ ",stdout);
        boxFg(tint[0],0);
        boxPutCell(names[i],t.cols[0].w);
        boxFg(BOX_FRAME,0);
        fputs(" │ ",stdout);
        boxFg(tint[1],0);
        boxFormatSize(sizes[i],text,sizeof(text));
        boxPutRight(text,t.cols[1].w);
        boxFg(BOX_FRAME,0);
        fputs(" │",stdout);
        if(nbCols == 3){
            size_t eighths = 0;
            if(biggest > 0){
                eighths = (size_t)((double)sizes[i] / (double)biggest * (double)(t.cols[2].w * 8) + 0.5);
                if(eighths == 0 && sizes[i] > 0){
                    eighths = 1;
                }
                if(eighths > t.cols[2].w * 8){
                    eighths = t.cols[2].w * 8;
                }
            }
            fputc(' ',stdout);
            boxPutBar(eighths,t.cols[2].w,tint[2]);
            boxFg(BOX_FRAME,0);
            fputs(" │",stdout);
        }
        boxReset();
        fputc('\n',stdout);
    }
    boxTableRule(&t,"└","┴","┘");
    return 0;
}

///////////////////////////// Liste des apps (bt_boxApps) et historique des mots de passe (bt_boxPwdHistory)

// Haut du cadre, total colonnes de large
static void boxPutTop(size_t total){
    boxFg(BOX_FRAME,0);
    fputs("┌",stdout);
    boxPutRepeat("─",total - 2);
    fputs("┐",stdout);
    boxReset();
    fputc('\n',stdout);
}

// Ligne de titre : head en gras, tail plus discret, le tout coupé avec « … » s'il dépasse avail colonnes
static void boxPutTitleRow(const char* head,const char* tail,size_t avail){
    size_t titleCols = boxCols(head) + boxCols(tail);
    size_t limit = (titleCols <= avail) ? avail : avail - 1;
    size_t used = 0;
    boxFg(BOX_FRAME,0);
    fputs("│ ",stdout);
    boxFg(BOX_TITLE,1);
    used += boxPutClip(head,limit - used);
    boxFg(BOX_SUBTITLE,0);
    used += boxPutClip(tail,limit - used);
    if(titleCols > avail){
        fputs("…",stdout);
        used++;
    }
    boxPutSpaces(avail - used);
    boxFg(BOX_FRAME,0);
    fputs(" │",stdout);
    boxReset();
    fputc('\n',stdout);
}

// En-têtes : la teinte de la colonne éclaircie, en gras. rightCol = colonne alignée à droite (-1 si aucune)
static void boxPutHeaderRow(const BoxTable* t,int rightCol){
    boxFg(BOX_FRAME,0);
    fputs("│",stdout);
    for(size_t k=0;k<t->nbOfCols;k++){
        fputc(' ',stdout);
        boxFg(boxLighten(t->cols[k].tint,40),1);
        if((int)k == rightCol){
            boxPutRight(t->cols[k].header,t->cols[k].w);
        }else{
            boxPutCell(t->cols[k].header,t->cols[k].w);
        }
        fputc(' ',stdout);
        boxFg(BOX_FRAME,0);
        fputs("│",stdout);
    }
    boxReset();
    fputc('\n',stdout);
}

int bt_boxApps(const CShieldAppInfo* apps,size_t nbOfApps){
    if(apps == NULL && nbOfApps > 0){
        LOG_ERROR("Corrupted pointer (apps == NULL)");
        return 1;
    }
    initConsole();
    if(nbOfApps == 0){
        print_INF("No app");
        return 0;
    }

    // Les ID d'une app sont mesurés et écrits comme les tags d'une entrée (séparés par ", ", coupés avec « … »)
    char text[32];
    char date[24];
    size_t totalEntries = 0;
    BoxTable t = {0};
    t.nbOfCols = 4;
    t.cols[0].header = "App";
    t.cols[1].header = "Entries";
    t.cols[2].header = "IDs";
    t.cols[3].header = "Updated";
    for(size_t k=0;k<4;k++){
        t.cols[k].w = boxCols(t.cols[k].header);
    }
    t.cols[3].w = 10;                        // "2026-11-10"
    for(size_t i=0;i<nbOfApps;i++){
        CShieldEntry ids = {0};
        ids.tags = apps[i].ids;
        ids.nbOfTags = apps[i].nbOfEntries;

        size_t w = boxCols(apps[i].app);
        if(w > t.cols[0].w){
            t.cols[0].w = w;
        }
        snprintf(text,sizeof(text),"%llu",(unsigned long long)apps[i].nbOfEntries);
        w = boxCols(text);
        if(w > t.cols[1].w){
            t.cols[1].w = w;
        }
        w = boxTagsCols(&ids);
        if(w > t.cols[2].w){
            t.cols[2].w = w;
        }
        totalEntries += apps[i].nbOfEntries;
    }
    for(size_t k=0;k<4;k++){
        size_t floorW = (boxCols(t.cols[k].header) > BOX_MIN_COL) ? boxCols(t.cols[k].header) : BOX_MIN_COL;
        int shrinkable = (k == 0 || k == 2);
        t.cols[k].minW = (shrinkable && floorW < t.cols[k].w) ? floorW : t.cols[k].w;
    }

    size_t maxW = boxMaxWidth();
    size_t appNaturalW = t.cols[0].w;
    int withIds = 1;
    if(!boxShrinkToFit(&t,maxW)){
        // Toujours trop large : on retire la colonne IDs (et les apps retrouvent leur largeur avant de rétrécir de nouveau)
        t.cols[2] = t.cols[3];
        t.nbOfCols = 3;
        t.cols[0].w = appNaturalW;
        withIds = 0;
        boxShrinkToFit(&t,maxW);
    }

    BoxRgb gradStart = {70,200,110};         // émeraude
    BoxRgb gradEnd = {90,205,175};           // vert d'eau
    for(size_t k=0;k<t.nbOfCols;k++){
        t.cols[k].tint = boxMix(gradStart,gradEnd,k,t.nbOfCols);
    }

    // Titre plus large que le tableau : on élargit la dernière colonne s'il reste de la place
    char tail[96];
    snprintf(tail,sizeof(tail)," · %llu %s · %llu %s",(unsigned long long)nbOfApps,(nbOfApps == 1) ? "app" : "apps",
             (unsigned long long)totalEntries,(totalEntries == 1) ? "entry" : "entries");
    size_t titleCols = boxCols("Apps") + boxCols(tail);
    size_t avail = boxTableWidth(&t) - 4;
    if(titleCols > avail && boxTableWidth(&t) + (titleCols - avail) <= maxW){
        t.cols[t.nbOfCols - 1].w += titleCols - avail;
        avail = titleCols;
    }

    boxPutTop(boxTableWidth(&t));
    boxPutTitleRow("Apps",tail,avail);
    boxTableRule(&t,"├","┬","┤");
    boxPutHeaderRow(&t,1);
    boxTableRule(&t,"├","┼","┤");

    // Lignes : une sur deux légèrement plus sombre. Une app vide affiche 0, « - » et « - ».
    for(size_t i=0;i<nbOfApps;i++){
        BoxRgb tint[4];
        for(size_t k=0;k<t.nbOfCols;k++){
            tint[k] = (i % 2 == 1) ? boxScale(t.cols[k].tint,84) : t.cols[k].tint;
        }
        boxFg(BOX_FRAME,0);
        fputs("│ ",stdout);
        boxFg(tint[0],0);
        boxPutCell(apps[i].app,t.cols[0].w);
        boxFg(BOX_FRAME,0);
        fputs(" │ ",stdout);
        boxFg(tint[1],0);
        snprintf(text,sizeof(text),"%llu",(unsigned long long)apps[i].nbOfEntries);
        boxPutRight(text,t.cols[1].w);
        boxFg(BOX_FRAME,0);
        fputs(" │ ",stdout);
        size_t last = 2;
        if(withIds){
            CShieldEntry ids = {0};
            ids.tags = apps[i].ids;
            ids.nbOfTags = apps[i].nbOfEntries;
            boxPutTagsCell(&ids,t.cols[2].w,tint[2]);
            boxFg(BOX_FRAME,0);
            fputs(" │ ",stdout);
            last = 3;
        }
        boxFormatDate(apps[i].updated,0,date,sizeof(date));
        boxFg(tint[last],0);
        boxPutCell(date,t.cols[last].w);
        boxFg(BOX_FRAME,0);
        fputs(" │",stdout);
        boxReset();
        fputc('\n',stdout);
    }
    boxTableRule(&t,"└","┴","┘");
    return 0;
}

// Numéro du jour (depuis le 1970-01-01) de "AAAA-MM-JJ..." ou -1 si la date est invalide
static long boxDayNumber(const char* iso){
    int y;
    int m;
    int d;
    if(iso == NULL || sscanf(iso,"%d-%d-%d",&y,&m,&d) != 3){
        return -1;
    }
    if(y < 1970 || m < 1 || m > 12 || d < 1 || d > 31){
        return -1;
    }
    if(m <= 2){
        y--;
    }
    long era = y / 400;
    long yoe = y - era * 400;
    long doy = (153 * (m + ((m > 2) ? -3 : 9)) + 2) / 5 + d - 1;
    long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

// L'historique d'une entrée a nbOfOldPassword + 1 lignes : la ligne 0 est le mot de passe actuel (entry->pwd),
// la ligne i >= 1 est entry->password_history[i - 1].
static const char* boxHistPwd(const CShieldEntry* e,size_t row){
    return (row == 0) ? e->pwd : e->password_history[row - 1];
}

// Date à laquelle le mot de passe de la ligne row a été défini. password_history_dates[row] est la date où password_history[row] (la ligne
// row + 1, plus ancienne) a été remplacé, donc celle où la ligne row a été définie. Le plus ancien n'a jamais été remplacé
// par rien : il date de la création de l'entrée.
static const char* boxHistSetOn(const CShieldEntry* e,size_t row){
    return (row < e->nbOfOldPassword) ? e->password_history_dates[row] : e->created;
}

// Durée d'usage du mot de passe de la ligne row : « current » pour le plus récent, sinon l'écart avec le suivant plus récent
static void boxUsedFor(const CShieldEntry* e,size_t i,char* out,size_t outSize){
    if(i == 0){
        snprintf(out,outSize,"current");
        return;
    }
    long newer = boxDayNumber(boxHistSetOn(e,i - 1));
    long older = boxDayNumber(boxHistSetOn(e,i));
    if(newer < 0 || older < 0 || newer < older){
        snprintf(out,outSize,"-");
    }else if(newer == older){
        snprintf(out,outSize,"< 1 day");
    }else if(newer - older == 1){
        snprintf(out,outSize,"1 day");
    }else{
        snprintf(out,outSize,"%ld days",newer - older);
    }
}

int bt_boxPwdHistory(const CShieldEntry* entry,int show){
    if(entry == NULL || (entry->nbOfOldPassword > 0 && (entry->password_history == NULL || entry->password_history_dates == NULL))){
        LOG_ERROR("Corrupted pointer (entry == NULL or password_history == NULL or password_history_dates == NULL)");
        return 1;
    }
    initConsole();
    if(bt_strlen(entry->pwd) == 0 && entry->nbOfOldPassword == 0){
        print_INF("No password history");
        return 0;
    }
    size_t nbOfPasswords = entry->nbOfOldPassword + 1;     // le mot de passe actuel + les anciens
    show = (show != 0);

    char text[32];
    char date[24];
    BoxTable t = {0};
    t.nbOfCols = 5;
    t.cols[0].header = "";
    t.cols[1].header = "Set on";
    t.cols[2].header = "Used for";
    t.cols[3].header = "Length";
    t.cols[4].header = "Password";
    for(size_t k=0;k<5;k++){
        t.cols[k].w = boxCols(t.cols[k].header);
    }
    t.cols[0].w = 1;                         // le marqueur ● du mot de passe actuel
    t.cols[1].w = BOX_DATE_COLS;
    for(size_t i=0;i<nbOfPasswords;i++){
        boxUsedFor(entry,i,text,sizeof(text));
        size_t w = boxCols(text);
        if(w > t.cols[2].w){
            t.cols[2].w = w;
        }
        snprintf(text,sizeof(text),"%llu",(unsigned long long)boxCols(boxHistPwd(entry,i)));
        w = boxCols(text);
        if(w > t.cols[3].w){
            t.cols[3].w = w;
        }
        w = show ? boxCols(boxHistPwd(entry,i)) : BOX_BULLETS_COLS;
        if(w > t.cols[4].w){
            t.cols[4].w = w;
        }
    }
    for(size_t k=0;k<5;k++){
        t.cols[k].minW = t.cols[k].w;
    }

    // Trop large avec les mots de passe masqués : la colonne Password ne sert à rien, on la retire
    size_t maxW = boxMaxWidth();
    int withPwd = 1;
    if(!show && boxTableWidth(&t) > maxW){
        t.nbOfCols = 4;
        withPwd = 0;
    }

    // Dégradé vertical : bleu ciel pour le plus récent, ardoise pour le plus ancien
    BoxRgb gradStart = {140,200,255};        // bleu ciel
    BoxRgb gradEnd = {105,120,150};          // ardoise
    for(size_t k=0;k<t.nbOfCols;k++){
        t.cols[k].tint = gradStart;
    }

    char head[512];
    snprintf(head,sizeof(head),"%s › %s",(entry->app != NULL) ? entry->app : "",(entry->id != NULL) ? entry->id : "");
    char tail[64];
    snprintf(tail,sizeof(tail)," · history · %llu %s",(unsigned long long)nbOfPasswords,(nbOfPasswords == 1) ? "password" : "passwords");
    size_t titleCols = boxCols(head) + boxCols(tail);
    size_t avail = boxTableWidth(&t) - 4;
    if(titleCols > avail && boxTableWidth(&t) + (titleCols - avail) <= maxW){
        t.cols[t.nbOfCols - 1].w += titleCols - avail;
        avail = titleCols;
    }

    boxPutTop(boxTableWidth(&t));
    boxPutTitleRow(head,tail,avail);
    boxTableRule(&t,"├","┬","┤");
    boxPutHeaderRow(&t,3);
    boxTableRule(&t,"├","┼","┤");

    // Lignes : la teinte descend avec l'âge, le mot de passe actuel porte le marqueur ● en gras
    for(size_t i=0;i<nbOfPasswords;i++){
        BoxRgb tint = boxMix(gradStart,gradEnd,i,nbOfPasswords);
        boxFg(BOX_FRAME,0);
        fputs("│ ",stdout);
        boxFg(tint,(i == 0) ? 1 : 0);
        fputs((i == 0) ? "●" : " ",stdout);
        boxFg(BOX_FRAME,0);
        fputs(" │ ",stdout);
        boxFg(tint,0);
        boxFormatDate(boxHistSetOn(entry,i),1,date,sizeof(date));
        boxPutCell(date,t.cols[1].w);
        boxFg(BOX_FRAME,0);
        fputs(" │ ",stdout);
        boxFg(tint,0);
        boxUsedFor(entry,i,text,sizeof(text));
        boxPutCell(text,t.cols[2].w);
        boxFg(BOX_FRAME,0);
        fputs(" │ ",stdout);
        boxFg(tint,0);
        snprintf(text,sizeof(text),"%llu",(unsigned long long)boxCols(boxHistPwd(entry,i)));
        boxPutRight(text,t.cols[3].w);
        boxFg(BOX_FRAME,0);
        fputs(" │",stdout);
        if(withPwd){
            fputc(' ',stdout);
            boxFg(tint,0);
            boxPutCell(show ? boxHistPwd(entry,i) : BOX_BULLETS,t.cols[4].w);
            boxFg(BOX_FRAME,0);
            fputs(" │",stdout);
        }
        boxReset();
        fputc('\n',stdout);
    }
    boxTableRule(&t,"└","┴","┘");
    return 0;
}

int bt_printInfo(){
    int state;
    // On récupére le path de la conf
    char* configPath = NULL;
    state = getConfPath(&configPath);
    if(state == 1){
        print_ERR("Impossible to fetch config path");
        return 1;
    }
    if(isFileOpenable(configPath) == 0){
        print_ERR("No config json found in %s",configPath);
        free(configPath);
        return 1;
    }
    // On récupére le JSON
    JsonValue conf = initCsonFromFile(configPath);
    if(conf.type == JSON_ERROR){
        print_ERR("No config json found in %s - Erreur CSON",configPath);
        free(configPath);
        return 1;
    }else if(conf.type != JSON_OBJECT){
        print_ERR("Config json altered (not an object)");
        freeValue(conf);
        free(configPath);
        return 1;
    }
    // vaultPath et actionLogPath pointent DANS conf : ne jamais les free (freeValue(conf) s'en charge)
    char* vaultPath = NULL;
    size_t indexVault = getIndexFromObjectWithKey(conf.value.object,"vaults_dir_path");
    if(indexVault == (size_t)-1){
        print_ERR("Config json altered (key 'vaults_dir_path' not found)");
        freeValue(conf);
        free(configPath);
        return 1;
    }
    if(conf.value.object->listeOfPair[indexVault].value.type != JSON_STRING){
        print_ERR("Config json altered (key 'vaults_dir_path' is not a string)");
        freeValue(conf);
        free(configPath);
        return 1;
    }
    vaultPath = conf.value.object->listeOfPair[indexVault].value.value.string;
    // On récupére le path des log d'erreur
    char* errorLogPath = NULL;
    state = getErrorLogPath(&errorLogPath);
    if(state == 1){
        print_ERR("Impossible to fetch error log path");
        freeValue(conf);
        free(configPath);
        return 1;
    }
    // On récupére le path des log d'action
    char* actionLogPath = NULL;
    size_t indexActionLog = getIndexFromObjectWithKey(conf.value.object,"log_action_path");
    if(indexActionLog == (size_t)-1){
        print_ERR("Config json altered (key 'log_action_path' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(conf.value.object->listeOfPair[indexActionLog].value.type != JSON_STRING){
        print_ERR("Config json altered (key 'log_action_path' is not a string)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    actionLogPath = conf.value.object->listeOfPair[indexActionLog].value.value.string;
    // On récupére le nombre d'itération PBKDF2
    size_t indexPBKDF2_iteration = getIndexFromObjectWithKey(conf.value.object,"pbkdf2_iterations");
    if(indexPBKDF2_iteration == (size_t)-1){
        print_ERR("Config json altered (key 'pbkdf2_iterations' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(conf.value.object->listeOfPair[indexPBKDF2_iteration].value.type != JSON_NUMBER){
        print_ERR("Config json altered (key 'pbkdf2_iterations' is not a number)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int PBKDF2_iteration = conf.value.object->listeOfPair[indexPBKDF2_iteration].value.value.integer;
    // On récupére le param de logAction
    size_t indexLogActionStatu = getIndexFromObjectWithKey(conf.value.object,"log_action");
    if(indexLogActionStatu == (size_t)-1){
        print_ERR("Config json altered (key 'log_action' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(conf.value.object->listeOfPair[indexLogActionStatu].value.type != JSON_BOOL){
        print_ERR("Config json altered (key 'log_action' is not a boolean)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int logActionStatu = conf.value.object->listeOfPair[indexLogActionStatu].value.value.integer;
    // On récupére le param de generation
    size_t indexGenerator = getIndexFromObjectWithKey(conf.value.object,"generator");
    if(indexGenerator == (size_t)-1){
        print_ERR("Config json altered (key 'generator' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(conf.value.object->listeOfPair[indexGenerator].value.type != JSON_OBJECT){
        print_ERR("Config json altered (conf>generator is not an object)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    JsonObject* generator = conf.value.object->listeOfPair[indexGenerator].value.value.object;
    //length
    size_t indexLenght = getIndexFromObjectWithKey(generator,"length");
    if(indexLenght == (size_t)-1){
        print_ERR("Config json altered (key 'length' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(generator->listeOfPair[indexLenght].value.type != JSON_NUMBER){
        print_ERR("Config json altered (key 'length' is not a number)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int length = generator->listeOfPair[indexLenght].value.value.integer;
    //uppercase
    size_t indexUppercase = getIndexFromObjectWithKey(generator,"uppercase");
    if(indexUppercase == (size_t)-1){
        print_ERR("Config json altered (key 'uppercase' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(generator->listeOfPair[indexUppercase].value.type != JSON_BOOL){
        print_ERR("Config json altered (key 'uppercase' is not a boolean)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int uppercase = generator->listeOfPair[indexUppercase].value.value.integer;
    //lowercase
    size_t indexLowercase = getIndexFromObjectWithKey(generator,"lowercase");
    if(indexLowercase == (size_t)-1){
        print_ERR("Config json altered (key 'lowercase' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(generator->listeOfPair[indexLowercase].value.type != JSON_BOOL){
        print_ERR("Config json altered (key 'lowercase' is not a boolean)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int lowercase = generator->listeOfPair[indexLowercase].value.value.integer;
    //digits
    size_t indexDigits = getIndexFromObjectWithKey(generator,"digits");
    if(indexDigits == (size_t)-1){
        print_ERR("Config json altered (key 'digits' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(generator->listeOfPair[indexDigits].value.type != JSON_BOOL){
        print_ERR("Config json altered (key 'digits' is not a boolean)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int digits = generator->listeOfPair[indexDigits].value.value.integer;
    //symbols
    size_t indexSymbols = getIndexFromObjectWithKey(generator,"symbols");
    if(indexSymbols == (size_t)-1){
        print_ERR("Config json altered (key 'symbols' not found)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    if(generator->listeOfPair[indexSymbols].value.type != JSON_BOOL){
        print_ERR("Config json altered (key 'symbols' is not a boolean)");
        freeValue(conf);
        free(configPath);
        free(errorLogPath);
        return 1;
    }
    int symbols = generator->listeOfPair[indexSymbols].value.value.integer;

    printf("\n");
    printf_RGB_BG(15,23,42,96,165,250," CShield v%.1f ",getVersionCShield());printf_RGB(148,163,184,"  First CLI build");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(96,165,250,"  %-14s","Config");printf_RGB(148,163,184,"%s",configPath);printf("\n");
    printf_RGB(96,165,250,"  %-14s","Vaults");printf_RGB(148,163,184,"%s",vaultPath);printf("\n");
    printf_RGB(96,165,250,"  %-14s","Error logs");printf_RGB(148,163,184,"%s",errorLogPath);printf("\n");
    printf_RGB(96,165,250,"  %-14s","Action logs");printf_RGB(148,163,184,"%s",actionLogPath);printf("   ");if(logActionStatu){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(96,165,250,"  %-14s","PBKDF2");printf_RGB(148,163,184,"%d iterations",PBKDF2_iteration);printf("\n");
    printf_RGB(96,165,250,"  %-14s","Length");printf_RGB(148,163,184,"%d characters",length);printf("\n");
    printf_RGB(96,165,250,"  %-14s","Characters");
    printf_RGB(148,163,184,"A-Z ");if(uppercase){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("   ");
    printf_RGB(148,163,184,"a-z ");if(lowercase){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("   ");
    printf_RGB(148,163,184,"0-9 ");if(digits){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("   ");
    printf_RGB(148,163,184,"sym ");if(symbols){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");

    freeValue(conf);
    free(configPath);
    free(errorLogPath);  
    return 0;
}

int bt_printHelp(){
    printf("\n");
    printf_RGB_BG(15,23,42,96,165,250," CShield v%.1f ",VERSION_CSHIELD);printf_RGB(148,163,184,"  Help");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(148,163,184,"  Usage       ");printf("cshield <command> <vault> [options]\n");
    printf("              cshield gen [options]\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(148,163,184,"  Commands");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-6s","create","crt");printf_RGB(148,163,184,"Add an entry to a vault");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-6s","modify","mdf");printf_RGB(148,163,184,"Change an entry, rename an application or an ID");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-6s","delete","dlt");printf_RGB(148,163,184,"Remove an entry, or a whole application");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-6s","show","shw");printf_RGB(148,163,184,"Show entries or search (alone: list the apps)");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-6s","generate","gen");printf_RGB(148,163,184,"Generate a password (no vault needed)");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(148,163,184,"  Vaults");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-9s","init","<vault>");printf_RGB(148,163,184,"Create a vault");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-9s","vaults","");printf_RGB(148,163,184,"List the vaults and their size");printf("\n");
    printf_RGB(96,165,250,"  %-9s%-9s","password","<vault>");printf_RGB(148,163,184,"Change the master password of a vault");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(148,163,184,"  Options");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--app","-a");printf_RGB(148,163,184,"Application name");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--id","-i");printf_RGB(148,163,184,"Entry identifier");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--note","-n");printf_RGB(148,163,184,"Note");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--tags","-t");printf_RGB(148,163,184,"Tags (modify replaces all, show filters)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--add-tags","-at");printf_RGB(148,163,184,"Add tags (modify only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--remove-tags","-rt");printf_RGB(148,163,184,"Remove tags (modify only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--new-app","-na");printf_RGB(148,163,184,"Rename an application (modify only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--new-id","-ni");printf_RGB(148,163,184,"Rename an entry (modify only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--password","-p");printf_RGB(148,163,184,"Set or change the password (create and modify only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--search","-se");printf_RGB(148,163,184,"Search words (show only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--and","");printf_RGB(148,163,184,"Match ALL tags / words (default, show only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--or","");printf_RGB(148,163,184,"Match ANY tag / word (show only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--show","-sh");printf_RGB(148,163,184,"Display passwords in clear (show only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--history","-h");printf_RGB(148,163,184,"Password history, with --app and --id (show only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--length","-len");printf_RGB(148,163,184,"Password length (generate only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--uppercase","-up");printf_RGB(148,163,184,"Toggle A-Z (generate only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--lowercase","-low");printf_RGB(148,163,184,"Toggle a-z (generate only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--digits","-dig");printf_RGB(148,163,184,"Use 0-9 (generate only)");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-6s","--symbols","-sym");printf_RGB(148,163,184,"Use symbols (generate only)");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(148,163,184,"  Examples");printf("\n");
    printf_RGB(74,222,128,"  cshield crt perso --app Google --id main --tags mail perso");printf("\n");
    printf_RGB(74,222,128,"  cshield mdf perso --app Google --id main --add-tags work");printf("\n");
    printf_RGB(74,222,128,"  cshield mdf perso --app Google --new-app Gmail");printf("\n");
    printf_RGB(74,222,128,"  cshield dlt perso --app Google --id main");printf("\n");
    printf_RGB(74,222,128,"  cshield shw perso");printf("\n");
    printf_RGB(74,222,128,"  cshield shw perso --app Google --id main --show");printf("\n");
    printf_RGB(74,222,128,"  cshield shw perso --app Google --id main --history");printf("\n");
    printf_RGB(74,222,128,"  cshield shw perso --tags mail perso --or");printf("\n");
    printf_RGB(74,222,128,"  cshield shw perso --search server");printf("\n");
    printf_RGB(74,222,128,"  cshield gen --length 24 --symbols");printf("\n");
    printf_RGB(74,222,128,"  cshield vaults");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    print_INF("Deleting without --id removes ALL entries of the application");
    print_INF("'-i' alone shows the configuration, after a command it means --id");
    print_INF("'generate' uses the conf.json defaults, flags toggle them");
    return 0;
}

int bt_printVersion(){
    printf("\n");
    printf_RGB_BG(15,23,42,96,165,250," CShield v%.1f ",VERSION_CSHIELD);printf_RGB(148,163,184,"  First CLI build");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    printf_RGB(148,163,184,"  %-15s%-10s%s","Component","Version","Source");printf("\n");
    printf_RGB(96,165,250,"  %-15s%-10.1f","CShield",VERSION_CSHIELD);printf_RGB(148,163,184,"https://github.com/BetaTetras/CShield");printf("\n");
    printf_RGB(74,222,128,"  %-15s%-10.1f","CSON",VERSION_CSON);printf_RGB(148,163,184,"https://github.com/BetaTetras/CSON");printf("\n");
    printf_RGB(248,113,113,"  %-15s%-10d","AES-256-GCM",VERSION_AES);printf_RGB(148,163,184,"https://github.com/BetaTetras/AES-256-GCM");printf("\n");
    printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
    return 0;
}
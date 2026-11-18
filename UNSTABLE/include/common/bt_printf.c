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

#ifdef _WIN32
    // Réglages d'origine de la console, pour les remettre à la fin du programme
    static UINT oldOutputCP = 0;
    static DWORD oldConsoleMode = 0;
    static int oldModeSaved = 0;

    static void restoreConsole(void){
        if(oldOutputCP != 0){
            SetConsoleOutputCP(oldOutputCP);
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
    const CShildEntry* entries;
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

int bt_boxSingleEntry(const CShildEntry* entry,int show){
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

static size_t boxTagsCols(const CShildEntry* e){
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
static size_t boxCellCols(const BoxTable* t,const BoxColumn* c,const CShildEntry* e){
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
static void boxPutTagsCell(const CShildEntry* e,size_t w,BoxRgb color){
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

static void boxPutRowCell(const BoxTable* t,const BoxColumn* c,const CShildEntry* e,size_t row){
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

int bt_boxMultiEntry(const CShildEntry* entries,size_t nbOfEntries,int show){
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

int bt_boxTagsMatching(const CShildEntry* entries,size_t nbOfEntries,int show,char** tags,size_t nbOfTags,char logicalOperator){
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

int bt_boxWordMatching(const CShildEntry* entries,size_t nbOfEntries,int show,char** words,size_t nbOfWords,char logicalOperator){
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

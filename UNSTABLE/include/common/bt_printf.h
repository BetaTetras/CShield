#ifndef BT_PRINTF_H
#define BT_PRINTF_H

#include <stddef.h>

#include "bt_utils.h"

// Affichage en couleur (codes ANSI 24 bits), messages à niveaux et boîtes d'affichage de shw. Tout est écrit en UTF-8.
// Sous Windows, la console est passée en UTF-8 avec les codes ANSI activés au premier affichage,
// puis remise comme avant à la fin du programme. Rien à appeler pour ça.
// Les messages (printf_RGB, print_*) ne doivent jamais contenir de secret (mot de passe, note).
// Seules les boîtes, en bas de ce fichier, en affichent, et seulement quand on le demande (show = 1).

// Fait vérifier le format par gcc comme pour printf (types et nombre des arguments) : fmt = n° du paramètre format, args = n° du premier argument
#if defined(__MINGW32__) && !defined(__clang__)
    // MinGW : "printf" suivrait les règles de l'ancien printf de Microsoft (faux warning sur %zu, %lld...)
    #define BT_PRINTF_CHECK(fmt,args) __attribute__((format(gnu_printf,fmt,args)))
#elif defined(__GNUC__)
    #define BT_PRINTF_CHECK(fmt,args) __attribute__((format(printf,fmt,args)))
#else
    #define BT_PRINTF_CHECK(fmt,args)
#endif
void initConsole(void);
void printf_RGB(int r, int g, int b, const char* format, ...) BT_PRINTF_CHECK(4,5);                                // texte en couleur r,g,b (0..255)
void printf_RGB_BG(int fr, int fg, int fb, int br, int bg, int bb, const char* format, ...) BT_PRINTF_CHECK(7,8);  // texte f* sur fond b*
void char_RGB(int r, int g, int b, char c);

// Les messages sont des formats printf : print_ERR("Entrée %s/%s existe déjà", app, id).
// Une donnée de l'utilisateur va TOUJOURS dans un argument (%s), jamais comme format : print_ERR(texte) est une faille.
void print_ERR(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ✗  ERROR    en rouge
void print_INF(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ⓘ  INFO     en violet
void print_WRN(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ⚑  WARNING  en orange
void print_SUC(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ✓  SUCCESS  en vert

// Boîtes d'affichage de shw : cadre gris clair, couleurs ANSI 24 bits, tout en UTF-8.
// Les quatre fonctions renvoient 0 si tout va bien, 1 si un paramètre est invalide (écrit dans error.log).
//
// Règles communes :
//   - show vaut 1 pour afficher les mots de passe en clair, 0 pour les masquer (••••••••).
//   - La largeur suit le terminal (sinon la variable COLUMNS, sinon 80). Un texte trop long est coupé avec « … »,
//     sauf un mot de passe affiché (show = 1) qui n'est jamais coupé : il passe à la ligne dans la fiche, et dans les
//     tableaux les autres colonnes sont réduites en premier.
//   - Si un tableau ne tient toujours pas et que show vaut 0, la colonne Password est retirée.
//   - Les retours à la ligne, tabulations et autres caractères de contrôle d'un champ s'affichent comme des espaces
//     (ils ne peuvent ni casser le cadre ni envoyer de séquence d'échappement au terminal).
//   - Les champs lus sont ceux de CShildEntry : app, id, pwd (seulement si show = 1), note, tags, updated, created et
//     matchingSrc (boîte Word). Ils ne sont jamais modifiés ni copiés.
//   - Limite connue : les caractères larges (CJK, emoji) comptent pour une colonne alors qu'ils en occupent deux.

// Fiche d'une entrée (shw --app --id) : lignes Password, Tags, Note, Created, Updated. Dégradé chaud de ligne en ligne,
// libellé plus clair que sa valeur. Tags et note passent à la ligne.
int bt_boxSingleEntry(const CShildEntry* entry,int show);

// Toutes les entrées d'une app (shw --app) : colonnes ID, Password, Tags, Updated. Dégradé froid de colonne en colonne,
// une ligne sur deux légèrement plus sombre. Le titre est le nom de l'app de la première entrée.
// Avec nbOfEntries = 0, écrit un simple message (pas de boîte).
int bt_boxMultiEntry(const CShildEntry* entries,size_t nbOfEntries,int show);

// Résultat de shw --tags : colonnes App, ID, Password, Tags, Updated. Dégradé vert menthe vers citron de colonne en
// colonne, comme le tableau multi. tags / nbOfTags sont les tags cherchés, logicalOperator vaut '&' (tous) ou '|'
// (au moins un) : ils servent seulement au titre « Tags: a AND b · 3 entries ».
int bt_boxTagsMatching(const CShildEntry* entries,size_t nbOfEntries,int show,char** tags,size_t nbOfTags,char logicalOperator);

// Résultat de shw --search : colonnes App, ID, Password, Tags, Updated, Match. Dégradé violet vers magenta de colonne
// en colonne ; Match affiche entry.matchingSrc (par exemple « id, note »), « - » s'il est vide. words / nbOfWords
// sont les mots cherchés, logicalOperator vaut '&' ou '|' (titre « Search: a OR b · 2 entries »).
int bt_boxWordMatching(const CShildEntry* entries,size_t nbOfEntries,int show,char** words,size_t nbOfWords,char logicalOperator);

// Liste des vaults (CShild vaults) : colonnes Vault, Size (alignée à droite, en B / KB / MB / GB) et Compare, une barre
// proportionnelle au plus gros vault (barre pleine = le plus gros, précise au 1/8 de case, au moins 1/8 pour tout vault non vide).
// Dégradé corail vers or de colonne en colonne, une ligne sur deux légèrement plus sombre. Le titre donne le nombre de
// vaults et leur poids total. names[i] est le nom affiché (sans « .cshild ») et sizes[i] sa taille en octets.
// Si le terminal est trop étroit, la colonne Compare est retirée. Avec nbOfVaults = 0, écrit un simple message (pas de boîte).
// Renvoie 0 si tout va bien, 1 si names ou sizes est NULL alors que nbOfVaults > 0 (écrit dans error.log).
int bt_boxVaults(char** names,const size_t* sizes,size_t nbOfVaults);

// Liste des apps (shw sans filtre) : colonnes App, Entries (alignée à droite), IDs et Updated. Dégradé émeraude vers vert
// d'eau de colonne en colonne, une ligne sur deux légèrement plus sombre. Les IDs sont séparés par « , » et coupés avec « … ».
// Une app vide (nbOfEntries = 0) affiche 0, « - » et « - ». Si le terminal est trop étroit, la colonne IDs est retirée.
// Le titre donne le nombre d'apps et d'entrées. Aucun secret : pas de paramètre show.
// Avec nbOfApps = 0, écrit un simple message (pas de boîte). Renvoie 0 si tout va bien, 1 si apps est NULL alors que
// nbOfApps > 0 (écrit dans error.log).
int bt_boxApps(const CShildAppInfo* apps,size_t nbOfApps);

// Historique des mots de passe d'une entrée (shw --app --id --history) : colonnes Set on, Used for, Length et Password.
// history[0] est le mot de passe actuel (marqué ●, « current »), les suivants sont de plus en plus anciens : « Used for »
// est l'écart en jours avec le mot de passe qui l'a remplacé. Le dégradé est vertical, du bleu ciel (récent) à l'ardoise
// (ancien). entry ne sert qu'au titre (app › id). Avec show = 0, les mots de passe sont masqués (Length reste visible) et
// la colonne Password disparaît si le terminal est trop étroit ; avec show = 1 ils ne sont jamais coupés (la boîte peut
// alors dépasser le terminal). Avec nbOfPasswords = 0, écrit un simple message (pas de boîte).
// Renvoie 0 si tout va bien, 1 si entry est NULL ou history est NULL alors que nbOfPasswords > 0 (écrit dans error.log).
int bt_boxPwdHistory(const CShildEntry* entry,const CShildPwdHistory* history,size_t nbOfPasswords,int show);

#endif

//
// codice di prova
//

#include <stdio.h>
#include <string.h>

int func(int a, int b)
{
    int c = a + b;
    return c;
}

int main()
{
    /*
    int a, b, result;
    printf("Inserisci il valore di a: ");
    scanf("%d", &a);
    printf("Inserisci il valore di b: ");
    scanf("%d", &b);
    result = func(a, b);
    printf("Risultato somma: %d\n", result);
    */

    char stringa[10];
    char *pointer1;
    char *pointer2;
    int *indirizzo;

    strcpy(stringa, "Sheliak!\n");
    pointer1 = stringa;
    pointer2 = pointer1 + 2;
    indirizzo = &stringa;

    printf("%s", stringa);
    printf(pointer1);
    printf(pointer2);
    printf(indirizzo);
    printf(&pointer1);

    return 0;
}
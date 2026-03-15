//
// codice di prova
//

#include <stdio.h>

int func(int a, int b)
{
    int c = a + b;
    return c;
}

int main()
{
    int a, b, result;
    // inserisci il valore di a
    printf("Inserisci il valore di a: ");
    scanf("%d", &a);
    printf("Inserisci il valore di b: ");
    scanf("%d", &b);
    result = func(a, b);
    printf("Risultato somma: %d\n", result);
    return 0;
}
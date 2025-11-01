/*
* Ferramenta auxiliar para coletar uma análise de frequência de comprimentos de senha em wordlists como rockyou.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024
#define MAX_PASSWORD_LENGTH 256

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    int frequency[MAX_PASSWORD_LENGTH + 1] = {0};
    char line[MAX_LINE_LENGTH];
    int total_passwords = 0;
    int min_length = MAX_PASSWORD_LENGTH;
    int max_length = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';
            len--;
        }

        if (len <= MAX_PASSWORD_LENGTH) {
            frequency[len]++;
            total_passwords++;
            
            if (len < min_length) min_length = len;
            if (len > max_length) max_length = len;
        } else {
            fprintf(stderr, "Warning: Line exceeds maximum length of %d characters\n", MAX_PASSWORD_LENGTH);
        }
    }

    fclose(file);

    printf("\n=== Password Length Frequency Analysis ===\n");
    printf("Total passwords: %d\n", total_passwords);
    printf("Minimum length: %d\n", min_length);
    printf("Maximum length: %d\n", max_length);
    printf("\n%-10s %-12s %-12s %s\n", "Length", "Count", "Percentage", "Bar");
    printf("-----------------------------------------------------------\n");

    for (int i = min_length; i <= max_length; i++) {
        if (frequency[i] > 0) {
            float percentage = (float)frequency[i] / total_passwords * 100;
            printf("%-10d %-12d %-11.2f%% ", i, frequency[i], percentage);
            
            int bar_length = (int)(percentage / 2);
            for (int j = 0; j < bar_length && j < 50; j++) {
                printf("█");
            }
            printf("\n");
        }
    }

    printf("\n");
    return 0;
}

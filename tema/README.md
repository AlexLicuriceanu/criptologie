## Task 1 - Break the LFSR:

1. Stiind ca mesajul criptat incepe cu "CRYPTO_CTF{", am recuperat primii (88)
biti ai cheii facand XOR intre textul cunoscut si mesajul criptat.

2. Am ales ca stare initiala rezultatul de la pasul anterior pentru a rula
LFSR-ul si astfel am generat intreaga secventa de biti ai cheii.

3. In final, pentru a afla mesajul original, am aplicat XOR intre fluxul de
biti generat si mesajul criptat.


## Task 2 - Differential Cryptanalysis

1. Am generat 128 de perechi de mesaje astfel:
- Primul mesaj are primul si ultimul bit 0, iar restul de 62 de biti sunt aleatori.
Al doilea mesaj se obtine aplicand XOR intre primul mesaj si diferential.
- Creez alte 3 variatii ale acestei perechi prim complementarea MSB si/sau LSB.

2. Criptez plaintext-urile generate anterior folosind algoritmul nimbus.

3. Sunt selectate doar perechile care respecta conditiile:
- XOR-ul intre ciphertext-uri trebuie sa aiba bitii finali "10"
- Ultimul bit al ambelor mesaje trebuie sa fie 0.

4. Se rezolva ecuatia `DIFF * K' = C1 + C2 (mod 2^64)`, care are solutia
`K' = (C1 + C2) / gcd(DIFF, 2^64) * x (mod 2^63)`. Pentru a calcula inversul
multiplicativ am folosit algoritmul extins al lui Euclid, de unde rezulta o
posibila subcheie; a doua subcheie posibila este generata inversand MSB.

5. Pentru a determina subcheia, se extrage cea care apare de cele mai multe ori, se
calculeaza complementul sau, si se returneaza 4 variante: cheia, 
complementul, cheia XOR 1, complementul XOR 1.

6. Se verifica fiecare candidat de cheie aplicand inversul criptarii pentru
fiecare pereche de ciphertext-uri. Daca ciphertext-urile decriptate coincid
cu plaintext-urile, atunci cheia a fost gasita.

7. In final, se decripteaza mesajul cu cheia gasita, inversand algoritmul nimbus
runda cu runda.
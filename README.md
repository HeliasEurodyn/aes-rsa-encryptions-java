# RSA - AES Java Examples

Simple AES & RSA algorithms execution example in Java

### Execution output 

```sh
 ------ AES Algorithm ------ 
 
1. Data to be encrypted: 3BkfhH0IITz5fgPAgkV062d/vAvjDGIuTtjG4YFebOoroFtQADW59X1Wqz5QffeDDi8Qf1XkH5cAyVuIwOud7f2h+edi8uXHOFAMNnOpHdswcoqnox91O0lhtqT366ZxspzM/A==
2. Encrypted data: 7bVV2GdZ9c/k57o8f0zdRDUCW+PO3Um8vdLOIBDiuuzafG6S1/y2+ewso9WA3DPSI5HHZOBHhitOyTcAm++96o30MMWqhVuHlbpft+LS4ZxES0/srGlK6QkMxTL1hA9Wfw7w3iWc49A2d/a6LzvRxw==
3. Decrypted data: 3BkfhH0IITz5fgPAgkV062d/vAvjDGIuTtjG4YFebOoroFtQADW59X1Wqz5QffeDDi8Qf1XkH5cAyVuIwOud7f2h+edi8uXHOFAMNnOpHdswcoqnox91O0lhtqT366ZxspzM/A==
4. Encryption time (seconds): 1.0863
5. Decryption time (seconds): 0.0409

 ------ RSA Algorithm ------ 
 
1. Data to be encrypted: aclw92BMAhNpKvKhIFye80LaDg+epbd5Pi6ytAos9AI7AJqrVkTLTSK+m+/C8bO/CYOuwFk1shuqwIaa6pUzZQpE6a9NtX4aj94i3+wI2JbORFOd5w4zMtjW0t1RbkAY2ZEgbA==
2. Encrypted data: OSvFICNJEWJb1r2QIlqQIXCEd9DLldEUVFWwEzGTLO911Zu1To53Xy5sc8nnDYYbwVIal6Mcdk/kSIW1ruNGugnhDhwtNISbr7w3gRcPeR51f4F0UmuvgsUNXFw5SVluo13oSHZLEm1LEcbm9X9/z2EGUquj1x8b8FOfL03vL1y0FFzZbTC0bMyOSkDjJT5enDv4yiC+gmnqb1jsSwDJOehx3RgZGClCrDsWFMQH+DMSFuEdUMx72rnBPElh1PJrcQrufelodQRE5zJP+wBC9LgNdqcs0icgoMMBRe/Ngl5DkMDl+mC4RIQgQC5kep4pYD75dtPxnVWHrpBzhF8igQ==
3. Decrypted data: aclw92BMAhNpKvKhIFye80LaDg+epbd5Pi6ytAos9AI7AJqrVkTLTSK+m+/C8bO/CYOuwFk1shuqwIaa6pUzZQpE6a9NtX4aj94i3+wI2JbORFOd5w4zMtjW0t1RbkAY2ZEgbA==
4. Encryption time (seconds): 1.8289
5. Decryption time (seconds): 7.941
```

#### Classes

1. The ```Main``` class demonstrates the encryption decryption example 
2. The  ```encryption\AesEncryptionUtil``` class handles the encryption & decryption using AES algorithm
2. The  ```encryption\RsaEncryptionUtil``` class handles the encryption & decryption using RSA algorithm

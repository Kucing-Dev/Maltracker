## Apa itu Maltracker?
Maltracker adalah singkatan dari Malware Tracker — yaitu sebuah tool OSINT (Open Source Intelligence) yang digunakan untuk:
> Melacak, menganalisis, dan mengevaluasi hash file (seperti SHA256, MD5, SHA1) untuk mengetahui apakah file tersebut terdeteksi sebagai malware oleh berbagai antivirus, melalui integrasi dengan API dari VirusTotal.

 ![Tools](https://github.com/user-attachments/assets/65843941-e7f9-4a23-b13d-47e40d5aa087)

## Apa yang baru?
- Auto Hash File
  
```
  python3 maltracker.py --file nama_file.exe
   
```
`→ Otomatis hitung SHA-256, lalu query ke VirusTotal.`


- Scan Banyak Hash dari File  `.txt`

  ```
  python3 Maltracker.py --hashlist daftar_hash.txt

```
`Scan semua hash di file.`

## Goal
The password for the next level is stored in the file `data.txt`, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under `/tmp` in which you can work using `mkdir`. For example: `mkdir /tmp/myname123`. Then copy the datafile using `cp`, and rename it using `mv` (read the manpages!).

## Solution
First, we need to use `xxd` to revert the `data.txt` to a compressed file.
```sh
bandit12@bandit:/tmp/donttouchme$ xxd -r ./data.txt > file1
```
```sh
bandit12@bandit:/tmp/donttouchme$ file file1
file1: gzip compressed data, was "data2.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
```

Here, `file1` is a **gzip compressed data**, so we need to decompress it.
```sh
bandit12@bandit:/tmp/donttouchme$ gunzip file1
gzip: file1: unknown suffix -- ignored
```

To fix this, we change the suffix to `.gz` which results in our new filename `file1.gz`.
```sh
bandit12@bandit:/tmp/donttouchme$ mv file1 file1.gz
bandit12@bandit:/tmp/donttouchme$ gunzip file1.gz 
bandit12@bandit:/tmp/donttouchme$ ls
data.txt  file1
bandit12@bandit:/tmp/donttouchme$ file file1
file1: bzip2 compressed data, block size = 900k
```

Next, the output file `file1` is now a **bzip2 compressed data**.
```sh
bandit12@bandit:/tmp/donttouchme$ bunzip2 file1
bunzip2: Can't guess original name for file1 -- using file1.out
bandit12@bandit:/tmp/donttouchme$ file file1.out
file1.out: gzip compressed data, was "data4.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
```

Another **gzip compressed data** file, let's rename `file1.out` to `file2.gz` and decompress it.
```sh
bandit12@bandit:/tmp/donttouchme$ mv file1.out file2.gz
bandit12@bandit:/tmp/donttouchme$ gunzip file2.gz 
bandit12@bandit:/tmp/donttouchme$ ls
data.txt  file2
bandit12@bandit:/tmp/donttouchme$ file file2
file2: POSIX tar archive (GNU)
```

This time is a `tar archive` file, so we use `tar` to unarchive the file.
```sh
bandit12@bandit:/tmp/donttouchme$ tar xf file2
bandit12@bandit:/tmp/donttouchme$ ls
data5.bin  data.txt  file2
bandit12@bandit:/tmp/donttouchme$ file data5.bin
data5.bin: POSIX tar archive (GNU)
```

Another `tar archive` file, so let's do the same thing.
```sh
bandit12@bandit:/tmp/donttouchme$ tar xf data5.bin
bandit12@bandit:/tmp/donttouchme$ ls
data5.bin  data6.bin  data.txt  file2
bandit12@bandit:/tmp/donttouchme$ file data6.bin
data6.bin: bzip2 compressed data, block size = 900k
```

Decompress this **bzip2 compressed data** file.
```sh
bandit12@bandit:/tmp/donttouchme$ bunzip2 data6.bin
bunzip2: Can't guess original name for data6.bin -- using data6.bin.out
bandit12@bandit:/tmp/donttouchme$ file data6.bin.out
data6.bin.out: POSIX tar archive (GNU)
```

Unarchive `data6.bin.out`.
```sh
bandit12@bandit:/tmp/donttouchme$ tar xf data6.bin.out
bandit12@bandit:/tmp/donttouchme$ ls
data5.bin  data6.bin.out  data8.bin  data.txt  file2
bandit12@bandit:/tmp/donttouchme$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
```

Rename and decompress `data8.bin`.
```sh
bandit12@bandit:/tmp/donttouchme$ mv data8.bin data8.bin.gz
bandit12@bandit:/tmp/donttouchme$ gunzip data8.bin.gz 
bandit12@bandit:/tmp/donttouchme$ ls
data5.bin  data6.bin.out  data8.bin  data.txt  file2
bandit12@bandit:/tmp/donttouchme$ file data8.bin
data8.bin: ASCII text
```

ASCII text 🥳
```sh
bandit12@bandit:/tmp/donttouchme$ cat data8.bin
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```
> Finally, flag: `8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL`

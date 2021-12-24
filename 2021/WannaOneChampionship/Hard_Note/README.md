# hard_note

Vì bài này là một bài mình đánh giá ở mức độ medium-hard (đối với bản thân mình), và vì nó có rất nhiều kiến thức trong đó, nên mình chỉ tóm tắt bằng short writeup, các bạn có thể tự ngẫm tìm hiểu thêm vì nếu giải thích tất cả sẽ rất dài

## Phân tích đề

  - Đề cho là dạng heap exploitation trên libc 2.34
  
  - Số con trỏ heap tối đa là 8, cấp phát tối đa là 0x600
  
  - Không có hàm view để leak
  
  - Lỗi off-byte-one null byte overflow tại hàm `create_note()`
  
  - Đề leak cho 1 địa chỉ của heap
  
## libc 2.34 heap

Đối với libc 2.34, chúng ta có một vài điểm lưu ý:

  - Cơ chế safe-linking (các con trỏ tại single liked list sẽ được mã hóa dựa theo địa chỉ, chúng ta có thể pass qua phần này vì đề đã leak cho ta 1 địa chỉ sẵn của heap).
  
  - Các cơ chế tấn công không leak như FSOP cần phải thay đổi một chút, vì single liked list thì có mã hóa, còn double liked list thì không.
  
  - Các con trỏ nằm tại `tcache_pthread_struct` không bị mã hóa => chuyển tấn công FSOP lên `tcache_pthread_struct`
  
  - malloc_hook, free_hook, realloc_hook đều bị bỏ trên libc 2.34

## FSOP (File-Stream Oriented Programing)

Các bạn nên tham khảo từ angelboy [https://nightrainy.github.io/2019/08/07/play-withe-file-structure-%E6%90%AC%E8%BF%90/](https://nightrainy.github.io/2019/08/07/play-withe-file-structure-%E6%90%AC%E8%BF%90/)
  
## Tóm tắt solution

  - Nhận địa chỉ leak mà chương trình đưa để tính toán địa chỉ của các chunk
  
  - Dùng lỗi off by one để tấn công heap backward consolidate nhằm malloc về `tcache_pthread_struct`, bypass safe liking bằng địa chỉ được leak.
  
  - Tấn công `tcache_pthread_struct`, tạo và free 7 chunk tại 1 offset nào đó, sau đó tạo tiếp một fakechunk nằm trong `tcache_pthread_struct`, và đặt địa chỉ của nó tại một offset nào đó, cấp phát và free để fakechunk vừa tạo được đưa vào unsorted bin, lúc này `fakechunk->fd` là một địa chỉ thuộc libc và nó đang nằm trên một offset của `tcache_pthread_struct`, tiến hành malloc đúng size đó là ta có thể malloc vào một vùng nhớ trong libc.
  
  - Tấn công FSOP, thay đổi 2 byte cuối của địa chỉ unsorted-bin thành stdout (1/16 cơ hội thành công), tiến hành leak libc.
  
  - Tấn công FSOP lần nữa để lấy shell.
  
Full solution: [solve.py](src/solve.py)

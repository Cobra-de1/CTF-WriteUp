Modern Rome

Đề cung cấp cho ta file binary và source code.
Kiểm tra file binary

Source code được viết ở ngôn ngữ c++.


Phân tích source, ta thấy:
+) Hàm win() cho ta shell.
+) Ở cuối hàm main có dòng buf[ind] = val; buf là một mảng thuộc phân vùng bss, ind, val có kiểu dữ liệu int => vì không có kiểm tra điều kiện nên ta có thể dùng ghi đè vào 2 byte cuối của exit.got, lúc ban đầu exit.got sẽ có giá trị là exit.plt + 4, đè 2 byte để chuyển về hàm win(). Lúc sau khi chương trình gọi exit ở cuối hàm main, ta chạy được hàm win()
+) Hàm readtoman() đọc một chuỗi và chuyển về một số kiểu dữ liệu short (2 bytes), công thức chuyển là ‘\x00’ * a + ‘M’ * b + ‘C’ * c + ‘X’ * d + ‘I’ * e -> abcde. Nếu chỉ được phép ghi đè 4 số, số tối đa của ta sẽ là 9999 < 32767 => readtoman() trả về số dương. Tuy nhiên vòng for sẽ lặp thêm 1 lần null byte, giúp cho ta ghi được số thứ 5, lúc này ta có thể overflow biến res về số âm. 
(short)(-372) = 0xfe8c = 65164.
Sau đó địa chỉ hàm win là 0x4012F6, giá trị ban đầu của exit.got là 0x4011A4, ta sẽ đè 2 byte 0x12F6 (4854) vào 2 byte cuối exit.got. 
Exploit:

































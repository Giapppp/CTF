## HTB 2023: Perfect Synchronization
Đây là challenge mình cảm thấy thú vị nhất trong những challenge mình giải được trong giải này, vì thế mình muốn viết writeup chi tiết cho bài này, vì vốn Tiếng Anh hạn hẹp mà mình lại nhiều lời nên mình sẽ viết Tiếng Việt vậy :D 

## Perfect Synchronization
> The final stage of your initialization sequence is mastering cutting-edge technology tools that can be life-changing. One of these tools is quipqiup, an automated tool for frequency analysis and breaking substitution ciphers. This is the ultimate challenge, simulating the use of AES encryption to protect a message. Can you break it?

**Category**: Cryptography

[public files](https://github.com/Giapppp/CTF/tree/main/HTB/HTB%202023/Perfect%20Synchronization/public)

## Writeup
# 1. Phân tích
``` python
#!usr/bin/python3

from os import urandom
from Crypto.Cipher import AES
from secret import MESSAGE

assert all([x.isupper() or x in '{_} ' for x in MESSAGE])


class Cipher:

    def __init__(self):
        self.salt = urandom(15)
        key = urandom(16)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, message):
        return [self.cipher.encrypt(c.encode() + self.salt) for c in message]


def main():
    cipher = Cipher()
    encrypted = cipher.encrypt(MESSAGE)
    encrypted = "\n".join([c.hex() for c in encrypted])

    with open("output.txt", 'w+') as f:
        f.write(encrypted)


if __name__ == "__main__":
    main()
```
Các bạn có thể suy ra một vài điều khi đọc file trên như sau:
+ Toàn bộ MESSAGE đều **viết hoa**, đây là tính chất quan trọng.
+ Với mỗi kí tự trong MESSAGE, ta sẽ cộng thêm với 15 byte ngẫu nhiên, rồi sau đó dùng thuật toán mã hóa **AES**
+ Bài này sử dụng **AES** với chế độ mã hóa **ECB**, đây là điểm mấu chốt để chúng ta giải mã

# 2. ECB (Electronic Codebook)
Đây là chế độ mã hóa đơn giản nhất trong AES. Trong chế độ này, message sẽ được chia thành các khối bit có **độ dài bằng nhau**. Với mỗi khối dữ liệu, ta sẽ mã hóa **từng khối** với khóa cho trước để có được khối mã hóa tương ứng. 

![ECB](https://github.com/Giapppp/CTF/blob/main/HTB/HTB%202023/Perfect%20Synchronization/picture/Screenshot%202023-03-23%20231210.png)

Vậy sử dụng ECB nguy hiểm đến mức nào ? Việc mã hóa từng khối theo một cách tuần tự có thể khiến cho dữ liệu bị **lộ cấu trúc**, để có thể hình dung rõ hơn về việc bị lộ cấu trúc, các bạn có thể xem qua bức ảnh này:

![Penguin](https://github.com/Giapppp/CTF/blob/main/HTB/HTB%202023/Perfect%20Synchronization/picture/Screenshot%202023-03-24%20004932.png)

 Có thể thấy với việc sử dụng ECB, cấu trúc dữ liệu có thể bị lộ ra. Nếu như attacker biết một vài thông tin về dữ liệu, khả năng cao họ sẽ có thể khôi phục lại dữ liệu đó, đây chính là điều mà chúng ta dùng để giải quyết challenge này
 # 3. Khai thác thông tin
Kiến thức đã có đủ, ta bắt đầu làm bài thôi!
Vì với mỗi kí tự trong MESSAGE, 15 byte ngẫu nhiên sẽ được thêm vào rồi sau đó mã hóa nên ta chỉ quan tâm đến byte đầu tiên:

```python
cts = []
with open("output.txt", "r") as f:
	for _ in range(1479):
		cts.append(f.readline())

cts = [bytes.fromhex(ct[:2]) for ct in cts]
```

MESSAGE được cấu tạo từ 26 chữ cái viết hoa cùng với các kí tự { } _  và khoảng trắng (các kí tự { _ } nằm trong flag). Vì ý nghĩa của khoảng trắng và _ là như nhau nên mình sẽ bỏ _ đi, vậy MESSAGE được cấu tạo từ 29 kí tự khác nhau.

Vì được mã hóa bằng ECB, các byte đầu của ciphertext (thông tin được mã hóa) sẽ có cùng tính chất với MESSAGE, tức là được cấu tạo từ 29 kí tự khác nhau. Ta có thể kiểm tra:

```python
import string

alphabet = string.ascii_uppercase + "{ }"
syms = []
for ct in cts:
	if ct not in syms:
		syms.append(ct)

print(len(syms))
print(len(alphabet))
```

Chương trình trên sẽ in ra:
![](https://github.com/Giapppp/CTF/blob/main/HTB/HTB%202023/Perfect%20Synchronization/picture/336711106_705787337895603_1310398408998920420_n.png)

Vậy là có đúng 29 kí tự khác nhau như ta đã dự đoán. 
Vì số lượng byte khác nhau bằng với số kí tự khác nhau trong `alphabet`, ta có thể xây dựng một **ánh xạ** đi từ tập các byte đến các kí tự trong alphabet. Ánh xạ này là **song ánh**, tức là với mỗi byte trong tập các byte khác nhau, ta chỉ có thể tìm được 1 kí tự trong alphabet tương ứng. Từ đó, ta có thể khôi phục lại MESSAGE.

```python
message = ''
for ct in cts:
	message += alphabet[syms.index(ct)]
print(message)
```
Và chúng ta sẽ có **MESSAGE** !!!! :

    ABCDECFGHIJFJKHLMLIMLINJLCOIPFIQRCIAJGQIQRJQIMFIJFHISMTCFILQBCQGRIPAIUBMQQCFIKJFSEJSCIGCBQJMFIKCQQCBLIJFOIGPVNMFJQMPFLIPAIKCQQCBLIPGGEBIUMQRITJBHMFSIABCDECFGMCLIVPBCPTCBIQRCBCIMLIJIGRJBJGQCBMLQMGIOMLQBMNEQMPFIPAIKCQQCBLIQRJQIMLIBPESRKHIQRCILJVCIAPBIJKVPLQIJKKILJVWKCLIPAIQRJQIKJFSEJSCIMFIGBHWQJFJKHLMLIABCDECFGHIJFJKHLMLIJKLPIXFPUFIJLIGPEFQMFSIKCQQCBLIMLIQRCILQEOHIPAIQRCIABCDECFGHIPAIKCQQCBLIPBISBPEWLIPAIKCQQCBLIMFIJIGMWRCBQCYQIQRCIVCQRPOIMLIELCOIJLIJFIJMOIQPINBCJXMFSIGKJLLMGJKIGMWRCBLIABCDECFGHIJFJKHLMLIBCDEMBCLIPFKHIJINJLMGIEFOCBLQJFOMFSIPAIQRCILQJQMLQMGLIPAIQRCIWKJMFQCYQIKJFSEJSCIJFOILPVCIWBPNKCVILPKTMFSILXMKKLIJFOIMAIWCBAPBVCOINHIRJFOIQPKCBJFGCIAPBICYQCFLMTCIKCQQCBINPPXXCCWMFSIOEBMFSIUPBKOIUJBIMMINPQRIQRCINBMQMLRIJFOIQRCIJVCBMGJFLIBCGBEMQCOIGPOCNBCJXCBLINHIWKJGMFSIGBPLLUPBOIWEZZKCLIMFIVJ{PBIFCULWJWCBLIJFOIBEFFMFSIGPFQCLQLIAPBIURPIGPEKOILPKTCIQRCVIQRCIAJLQCLQILCTCBJKIPAIQRCIGMWRCBLIELCOINHIQRCIJYMLIWPUCBLIUCBCINBCJXJNKCIELMFSIABCDECFGHIJFJKHLMLIAPBICYJVWKCILPVCIPAIQRCIGPFLEKJBIGMWRCBLIELCOINHIQRCI{JWJFCLCIVCGRJFMGJKIVCQRPOLIPAIKCQQCBIGPEFQMFSIJFOILQJQMLQMGJKIJFJKHLMLISCFCBJKKHIRQNXJ LMVWKC LENLQMQEQMPF ML UCJX}IGJBOIQHWCIVJGRMFCBHIUCBCIAMBLQIELCOIMFIUPBKOIUJBIMMIWPLLMNKHINHIQRCIELIJBVHLILMLIQPOJHIQRCIRJBOIUPBXIPAIKCQQCBIGPEFQMFSIJFOIJFJKHLMLIRJLINCCFIBCWKJGCOINHIGPVWEQCBILPAQUJBCIURMGRIGJFIGJBBHIPEQILEGRIJFJKHLMLIMFILCGPFOLIUMQRIVPOCBFIGPVWEQMFSIWPUCBIGKJLLMGJKIGMWRCBLIJBCIEFKMXCKHIQPIWBPTMOCIJFHIBCJKIWBPQCGQMPFIAPBIGPFAMOCFQMJKIOJQJIWEZZKCIWEZZKCIWEZZKC
Hoặc không...

Các kí tự trong MESSAGE mà ta nhận được đều đã bị xáo trộn vị trí lại với nhau, do chúng ta chưa thể tìm ra kí tự trong `alphabet` tương ứng với mỗi byte khác nhau. Để khắc phục lỗi này, ta có thể sử dụng [**quipqiup**](https://quipqiup.com/) (nếu như bạn đọc kĩ description của challenge, bạn sẽ thấy cái tên này), một trang web giúp chúng ta tìm lại thứ tự đúng của các kí tự, từ đó in ra một nội dung có ý nghĩa:
![quipqiup](https://github.com/Giapppp/CTF/blob/main/HTB/HTB%202023/Perfect%20Synchronization/picture/Screenshot%202023-03-24%20000943.png)


Khi đưa MESSAGE của chúng ta vào trong quipqiup, ta sẽ nhận lại được đoạn MESSAGE khác:
```python
FREQUENCYKANALYSISKISKBASEDKONKTHEKFACTKTHATKINKANYKGIVENKSTRETCHKOFKWRITTENKLANGUAGEKCERTAINKLETTERSKANDKCOMBINATIONSKOFKLETTERSKOCCURKWITHKVARYINGKFREQUENCIESKMOREOVERKTHEREKISKAKCHARACTERISTICKDISTRIBUTIONKOFKLETTERSKTHATKISKROUGHLYKTHEKSAMEKFORKALMOSTKALLKSAMPLESKOFKTHATKLANGUAGEKINKCRYPTANALYSISKFREQUENCYKANALYSISKALSOKJNOWNKASKCOUNTINGKLETTERSKISKTHEKSTUDYKOFKTHEKFREQUENCYKOFKLETTERSKORKGROUPSKOFKLETTERSKINKAKCIPHERTEXTKTHEKMETHODKISKUSEDKASKANKAIDKTOKBREAJINGKCLASSICALKCIPHERSKFREQUENCYKANALYSISKREQUIRESKONLYKAKBASICKUNDERSTANDINGKOFKTHEKSTATISTICSKOFKTHEKPLAINTEXTKLANGUAGEKANDKSOMEKPROBLEMKSOLVINGKSJILLSKANDKIFKPERFORMEDKBYKHANDKTOLERANCEKFORKEXTENSIVEKLETTERKBOOJJEEPINGKDURINGKWORLDKWARKIIKBOTHKTHEKBRITISHKANDKTHEKAMERICANSKRECRUITEDKCODEBREAJERSKBYKPLACINGKCROSSWORDKPUZZLESKINKMA{ORKNEWSPAPERSKANDKRUNNINGKCONTESTSKFORKWHOKCOULDKSOLVEKTHEMKTHEKFASTESTKSEVERALKOFKTHEKCIPHERSKUSEDKBYKTHEKAXISKPOWERSKWEREKBREAJABLEKUSINGKFREQUENCYKANALYSISKFORKEXAMPLEKSOMEKOFKTHEKCONSULARKCIPHERSKUSEDKBYKTHEK{APANESEKMECHANICALKMETHODSKOFKLETTERKCOUNTINGKANDKSTATISTICALKANALYSISKGENERALLYKHTBJA SIMPLE SUBSTITUTION IS WEAJ}KCARDKTYPEKMACHINERYKWEREKFIRSTKUSEDKINKWORLDKWARKIIKPOSSIBLYKBYKTHEKUSKARMYSKSISKTODAYKTHEKHARDKWORJKOFKLETTERKCOUNTINGKANDKANALYSISKHASKBEENKREPLACEDKBYKCOMPUTERKSOFTWAREKWHICHKCANKCARRYKOUTKSUCHKANALYSISKINKSECONDSKWITHKMODERNKCOMPUTINGKPOWERKCLASSICALKCIPHERSKAREKUNLIJELYKTOKPROVIDEKANYKREALKPROTECTIONKFORKCONFIDENTIALKDATAKPUZZLEKPUZZLEKPUZZLE
```
Ta có thể nhìn thấy một số cụm từ tiếng anh như "FREQUENCY", "ANALYSIS", ... Giữa các cụm từ đó có chữ K, vậy chữ K này đóng vai trò như khoảng trắng, ta sẽ thử thay thế K bằng khoảng trắng để xem có gì bất ngờ không:
```python
message = 'FREQUENCYKANALYSISKISKBASEDKONKTHEKFACTKTHATKINKANYKGIVENKSTRETCHKOFKWRITTENKLANGUAGEKCERTAINKLETTERSKANDKCOMBINATIONSKOFKLETTERSKOCCURKWITHKVARYINGKFREQUENCIESKMOREOVERKTHEREKISKAKCHARACTERISTICKDISTRIBUTIONKOFKLETTERSKTHATKISKROUGHLYKTHEKSAMEKFORKALMOSTKALLKSAMPLESKOFKTHATKLANGUAGEKINKCRYPTANALYSISKFREQUENCYKANALYSISKALSOKJNOWNKASKCOUNTINGKLETTERSKISKTHEKSTUDYKOFKTHEKFREQUENCYKOFKLETTERSKORKGROUPSKOFKLETTERSKINKAKCIPHERTEXTKTHEKMETHODKISKUSEDKASKANKAIDKTOKBREAJINGKCLASSICALKCIPHERSKFREQUENCYKANALYSISKREQUIRESKONLYKAKBASICKUNDERSTANDINGKOFKTHEKSTATISTICSKOFKTHEKPLAINTEXTKLANGUAGEKANDKSOMEKPROBLEMKSOLVINGKSJILLSKANDKIFKPERFORMEDKBYKHANDKTOLERANCEKFORKEXTENSIVEKLETTERKBOOJJEEPINGKDURINGKWORLDKWARKIIKBOTHKTHEKBRITISHKANDKTHEKAMERICANSKRECRUITEDKCODEBREAJERSKBYKPLACINGKCROSSWORDKPUZZLESKINKMA{ORKNEWSPAPERSKANDKRUNNINGKCONTESTSKFORKWHOKCOULDKSOLVEKTHEMKTHEKFASTESTKSEVERALKOFKTHEKCIPHERSKUSEDKBYKTHEKAXISKPOWERSKWEREKBREAJABLEKUSINGKFREQUENCYKANALYSISKFORKEXAMPLEKSOMEKOFKTHEKCONSULARKCIPHERSKUSEDKBYKTHEK{APANESEKMECHANICALKMETHODSKOFKLETTERKCOUNTINGKANDKSTATISTICALKANALYSISKGENERALLYKHTBJA SIMPLE SUBSTITUTION IS WEAJ}KCARDKTYPEKMACHINERYKWEREKFIRSTKUSEDKINKWORLDKWARKIIKPOSSIBLYKBYKTHEKUSKARMYSKSISKTODAYKTHEKHARDKWORJKOFKLETTERKCOUNTINGKANDKANALYSISKHASKBEENKREPLACEDKBYKCOMPUTERKSOFTWAREKWHICHKCANKCARRYKOUTKSUCHKANALYSISKINKSECONDSKWITHKMODERNKCOMPUTINGKPOWERKCLASSICALKCIPHERSKAREKUNLIJELYKTOKPROVIDEKANYKREALKPROTECTIONKFORKCONFIDENTIALKDATAKPUZZLEKPUZZLEKPUZZLE'
print(message.replace("K", " "))
```
Chương trình sẽ in ra:
![](https://github.com/Giapppp/CTF/blob/main/HTB/HTB%202023/Perfect%20Synchronization/picture/336289483_1148115492536604_2198124458387426435_n.png)
Nếu đọc kĩ, ta có thể thấy được một đoạn rất khả nghi :D

    HTBJA SIMPLE SUBSTITUTION IS WEAJ}
Bằng cách đổi lại một vài chữ, thay đổi khoảng trắng bằng dấu _ và chỉnh lại sao cho đúng flag format, ta sẽ có flag:

    HTB{A_SIMPLE_SUBSTITUTION_IS_WEAK}

# 4. Tổng kết
Đây là một challenge ở mức very easy, nhưng đối với mình quá trình làm bài này là thú vị nhất trong những bài mình giải được. Các bạn có thể xem qua lời giải những bài khác của mình trong [github](https://github.com/Giapppp/CTF/tree/main/HTB/HTB%202023). ECB là chế độ mã hóa yếu nhất của AES, vì vậy rất hay được sử dụng trong các cuộc thi CTF nhưng không bao giờ được sử dụng ngoài đời, có cả một [bài thơ](https://gist.github.com/unicornsasfuel/f29c4397ff87a95f25af03246c1a1ed4) để nói về việc cấm sử dụng nó luôn, nếu rảnh thì các bạn có thể đọc :)

Cám ơn các bạn đã đọc đến dòng này. Mình viết dài lắm á :))
>Giapppp from phis1Ng_

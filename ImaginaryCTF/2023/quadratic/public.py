from Crypto.Util.number import bytes_to_long

x = bytes_to_long(b'ictf{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}')
print(69*x^2 + 42*x + 314159265358)

# 11579616830010600399932641971351067137758799841099537906925885183536730818623058070093057619806810857320199981348668999197653583956890465217095149031820045015395
with open(r'C:\Users\Racem\Desktop\soc_siem_pro\soc_siem_pro\gui\app.py') as f:
    lines = f.readlines()

# Remove duplicate line 358 (index 357) and fix line 357 (index 356)
lines[356] = '    def show_context_menu(self, pos):\n'
del lines[357]

with open(r'C:\Users\Racem\Desktop\soc_siem_pro\soc_siem_pro\gui\app.py', 'w') as f:
    f.writelines(lines)
print("fixed OK")

from ui.signals import UISignals
from core.misc import VendorOUI, Settings, Translations, PCAPWritter

class AppCore:
    
    def __init__(self):
        self.VendorOUI    = VendorOUI()
        self.Settings     = Settings()
        self.Translations = Translations(self.Settings.get("lang", "EN"))
        self.UISignals    = UISignals()
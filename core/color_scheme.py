try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = RESET_ALL = BRIGHT = ""

    Fore = Back = Style = _NoColor()

    def init(*args, **kwargs):
        return None


class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_YELLOW = Back.YELLOW
    BG_BLUE = Back.BLUE
    BG_MAGENTA = Back.MAGENTA
    BG_CYAN = Back.CYAN
    
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL
    
    SEV_CRITICAL = RED + BRIGHT
    SEV_HIGH = YELLOW + BRIGHT
    SEV_MEDIUM = BLUE + BRIGHT
    SEV_LOW = GREEN + BRIGHT
    SEV_INFO = CYAN

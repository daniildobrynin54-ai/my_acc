"""Модуль авторизации с поддержкой прокси и cookies."""

from typing import Optional, Dict
import requests
from bs4 import BeautifulSoup

from config import BASE_URL, USER_AGENT, REQUEST_TIMEOUT
from rate_limiter import RateLimitedSession
from proxy_manager import ProxyManager


class AuthenticationError(Exception):
    """Ошибка аутентификации."""
    pass


def get_csrf_token(session: requests.Session) -> Optional[str]:
    """Получает CSRF токен со страницы логина."""
    try:
        response = session.get(f"{BASE_URL}/login", timeout=REQUEST_TIMEOUT)
        
        if response.status_code != 200:
            return None
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Пробуем найти токен в meta теге
        token_meta = soup.select_one('meta[name="csrf-token"]')
        if token_meta:
            token = token_meta.get("content", "").strip()
            if token:
                return token
        
        # Пробуем найти токен в input поле
        token_input = soup.find("input", {"name": "_token"})
        if token_input:
            token = token_input.get("value", "").strip()
            if token:
                return token
        
        return None
        
    except requests.RequestException:
        return None


def create_session(proxy_manager: Optional[ProxyManager] = None) -> requests.Session:
    """
    Создает настроенную сессию requests с прокси.
    
    Args:
        proxy_manager: Менеджер прокси
    
    Returns:
        Настроенная сессия с rate limiting
    """
    session = requests.Session()
    
    # Настраиваем прокси
    if proxy_manager and proxy_manager.is_enabled():
        proxies = proxy_manager.get_proxies()
        if proxies:
            session.proxies.update(proxies)
            proxy_info = proxy_manager.get_info()
            print(f"🔗 Используется прокси: {proxy_info}")
    
    # Настраиваем заголовки
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en;q=0.8",
    })
    
    # Оборачиваем в RateLimitedSession
    return RateLimitedSession(session)


def create_session_from_cookies(
    cookies_dict: Dict[str, str],
    csrf_token: Optional[str] = None,
    proxy_manager: Optional[ProxyManager] = None
) -> Optional[RateLimitedSession]:
    """
    🔧 НОВОЕ: Создает авторизованную сессию из готовых cookies.
    
    Args:
        cookies_dict: Словарь с cookies (обязательно должен содержать mangabuff_session)
        csrf_token: CSRF токен (опционально, можно получить автоматически)
        proxy_manager: Менеджер прокси
    
    Returns:
        Авторизованная сессия или None при ошибке
    
    Example:
        cookies = {
            "mangabuff_session": "eyJpdiI6Ik...",
            "XSRF-TOKEN": "eyJpdiI6Ik..."
        }
        session = create_session_from_cookies(cookies, "your-csrf-token")
    """
    # Проверяем наличие основной cookie сессии
    if "mangabuff_session" not in cookies_dict:
        print("⚠️  Ошибка: отсутствует mangabuff_session в cookies")
        return None
    
    print("🔐 Создание сессии из cookies...")
    
    # Создаем базовую сессию
    session = create_session(proxy_manager)
    
    # Добавляем cookies
    for name, value in cookies_dict.items():
        session._session.cookies.set(name, value, domain="mangabuff.ru", path="/")
    
    print(f"   Загружено cookies: {len(cookies_dict)}")
    
    # Если токен не предоставлен, пробуем получить автоматически
    if not csrf_token:
        print("   Получение CSRF токена...")
        csrf_token = get_csrf_token(session)
        
        if csrf_token:
            print(f"   ✅ CSRF токен получен автоматически")
        else:
            # Пробуем извлечь из cookies
            if "XSRF-TOKEN" in cookies_dict:
                csrf_token = cookies_dict["XSRF-TOKEN"]
                print(f"   ✅ CSRF токен извлечен из cookies")
    
    # Устанавливаем токен в заголовки
    if csrf_token:
        session.headers.update({
            "X-CSRF-TOKEN": csrf_token,
            "X-Requested-With": "XMLHttpRequest"
        })
        print(f"   CSRF токен установлен в заголовки")
    else:
        print("   ⚠️  Не удалось получить CSRF токен (может работать без него)")
    
    # Проверяем авторизацию
    if not is_authenticated(session):
        print("⚠️  Авторизация не подтверждена (проверьте актуальность cookies)")
        return None
    
    print("✅ Сессия успешно создана из cookies\n")
    return session


def login(
    email: str,
    password: str,
    proxy_manager: Optional[ProxyManager] = None
) -> Optional[RateLimitedSession]:
    """
    Выполняет вход в аккаунт через email/password.
    
    Args:
        email: Email пользователя
        password: Пароль
        proxy_manager: Менеджер прокси
    
    Returns:
        Авторизованная сессия или None при ошибке
    
    Raises:
        AuthenticationError: При ошибке аутентификации
    """
    session = create_session(proxy_manager)
    
    csrf_token = get_csrf_token(session)
    if not csrf_token:
        print("⚠️  Не удалось получить CSRF токен")
        return None
    
    headers = {
        "Referer": f"{BASE_URL}/login",
        "Origin": BASE_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRF-TOKEN": csrf_token,
    }
    
    data = {
        "email": email,
        "password": password,
        "_token": csrf_token
    }
    
    try:
        response = session.post(
            f"{BASE_URL}/login",
            data=data,
            headers=headers,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT
        )
        
        # Проверяем успешность входа по наличию cookie сессии
        if "mangabuff_session" not in session.cookies:
            print("⚠️  Авторизация не удалась: нет cookie сессии")
            return None
        
        # Обновляем заголовки для последующих запросов
        session.headers.update({
            "X-CSRF-TOKEN": csrf_token,
            "X-Requested-With": "XMLHttpRequest"
        })
        
        return session
        
    except requests.RequestException as e:
        print(f"⚠️  Ошибка при авторизации: {e}")
        return None


def is_authenticated(session: requests.Session) -> bool:
    """
    Проверяет, авторизована ли сессия.
    
    Args:
        session: Сессия для проверки
    
    Returns:
        True если сессия авторизована
    """
    # Для RateLimitedSession нужно обращаться к _session
    if isinstance(session, RateLimitedSession):
        return "mangabuff_session" in session._session.cookies
    else:
        return "mangabuff_session" in session.cookies


def get_cookies_from_session(session: requests.Session) -> Dict[str, str]:
    """
    🔧 НОВОЕ: Извлекает cookies из сессии в виде словаря.
    
    Полезно для сохранения cookies после успешного логина.
    
    Args:
        session: Сессия requests
    
    Returns:
        Словарь с cookies
    """
    if isinstance(session, RateLimitedSession):
        cookies = session._session.cookies
    else:
        cookies = session.cookies
    
    return {cookie.name: cookie.value for cookie in cookies}


def print_cookies_for_config(session: requests.Session) -> None:
    """
    🔧 НОВОЕ: Выводит cookies в формате для копирования в config.py.
    
    Args:
        session: Авторизованная сессия
    """
    cookies = get_cookies_from_session(session)
    csrf_token = session.headers.get('X-CSRF-TOKEN', '')
    
    print("\n" + "=" * 60)
    print("📋 COOKIES ДЛЯ config.py")
    print("=" * 60)
    print("\nСкопируйте это в config.py:\n")
    print("# Cookies для авторизации")
    print("AUTH_COOKIES = {")
    for name, value in cookies.items():
        # Скрываем часть значения для безопасности
        if len(value) > 20:
            safe_value = value[:10] + "..." + value[-10:]
        else:
            safe_value = value
        print(f'    "{name}": "{value}",  # {safe_value}')
    print("}")
    print(f'\nAUTH_CSRF_TOKEN = "{csrf_token}"\n')
    print("=" * 60 + "\n")
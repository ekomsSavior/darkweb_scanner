from .base_check import BaseCheck
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class FormDetectorCheck(BaseCheck):
    """Detect and analyze HTML forms for login panels, uploads, and hidden inputs"""

    def __init__(self):
        super().__init__()
        self.name = "Form Detector"
        self.description = "Detects login forms, file uploads, hidden inputs, and form actions"

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp or not resp.text:
            return findings

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
        except Exception:
            return findings

        forms = soup.find_all('form')
        if not forms:
            return findings

        login_forms = []
        upload_forms = []
        search_forms = []
        other_forms = []

        for form in forms:
            action = form.get('action', '')
            method = (form.get('method', 'GET')).upper()
            form_id = form.get('id', '')
            form_class = ' '.join(form.get('class', []))
            enctype = form.get('enctype', '')

            inputs = form.find_all('input')
            input_types = [i.get('type', 'text').lower() for i in inputs]
            input_names = [i.get('name', '').lower() for i in inputs]

            hidden_inputs = []
            for i in inputs:
                if i.get('type', '').lower() == 'hidden':
                    hidden_inputs.append({
                        'name': i.get('name', ''),
                        'value': i.get('value', '')[:50]
                    })

            form_info = {
                'action': urljoin(url, action) if action else url,
                'method': method,
                'id': form_id,
                'inputs': len(inputs),
                'hidden_count': len(hidden_inputs),
                'hidden_inputs': hidden_inputs
            }

            # Classify the form
            # FIX: Operator precedence bug. `and` binds tighter than `or`, so the
            # original expression parsed as:
            #   password_in_types OR password_in_names OR (username_in_names AND password_in_types)
            # The third clause was redundant (if password_in_types is True, the first
            # clause already matches). Added explicit parentheses for clarity.
            has_password = ('password' in input_types or
                           any(n in input_names for n in ['password', 'passwd', 'pwd', 'pass']))
            has_username = any(n in input_names for n in ['username', 'user', 'login', 'email'])
            is_login = has_password or (has_username and has_password)

            is_upload = ('file' in input_types or
                         enctype == 'multipart/form-data')

            is_search = (any(n in input_names for n in ['search', 'query', 'q', 'keyword']) or
                         'search' in form_id.lower() or
                         'search' in form_class.lower())

            if is_login:
                login_forms.append(form_info)
            elif is_upload:
                upload_forms.append(form_info)
            elif is_search:
                search_forms.append(form_info)
            else:
                other_forms.append(form_info)

        # Build findings
        if login_forms:
            details = []
            for f in login_forms:
                details.append(f"  Action: {f['action']} ({f['method']}), {f['inputs']} inputs")
                if f['hidden_inputs']:
                    for h in f['hidden_inputs']:
                        details.append(f"    Hidden: {h['name']}={h['value']}")
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Login forms: {len(login_forms)} detected",
                'detail': '\n'.join(details),
                'url': url,
                'data': {'login_forms': login_forms}
            })

        if upload_forms:
            details = [f"  Action: {f['action']} ({f['method']})" for f in upload_forms]
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"File upload forms: {len(upload_forms)} detected",
                'detail': '\n'.join(details),
                'url': url,
                'data': {'upload_forms': upload_forms}
            })

        if search_forms:
            details = [f"  Action: {f['action']} ({f['method']})" for f in search_forms]
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Search forms: {len(search_forms)} detected",
                'detail': '\n'.join(details),
                'url': url
            })

        # Report all hidden inputs (potential CSRF tokens, session IDs, etc.)
        all_hidden = []
        for form_list in [login_forms, upload_forms, search_forms, other_forms]:
            for f in form_list:
                all_hidden.extend(f.get('hidden_inputs', []))

        if all_hidden:
            interesting_hidden = [h for h in all_hidden if h['value'] and
                                   h['name'].lower() not in ('', 'submit', 'action')]
            if interesting_hidden:
                details = [f"  {h['name']}={h['value']}" for h in interesting_hidden[:15]]
                findings.append({
                    'check': self.name,
                    'severity': 'medium',
                    'finding': f"Hidden form inputs: {len(interesting_hidden)} with values",
                    'detail': '\n'.join(details),
                    'url': url,
                    'data': {'hidden_inputs': interesting_hidden}
                })

        if other_forms:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Other forms: {len(other_forms)} detected",
                'detail': '\n'.join([f"  {f['action']} ({f['method']})" for f in other_forms[:10]]),
                'url': url
            })

        return findings

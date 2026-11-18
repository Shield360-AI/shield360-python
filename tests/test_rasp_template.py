"""Template-source detection and hooks (sdk/rasp/README.md, "Template source").
Detector checks mirror sdk/typescript/src/rasp/__tests__/template-hook.test.ts;
the hooks run against stand-in engines, and against Jinja2, Mako and Django
when they are installed."""

import sys
import types

import pytest

from rasp_corpus import load_json
from rasp_hook_kit import in_request, req, stop_engine, use_engine
from shield360.rasp import _template
from shield360.rasp._hooks.template import install_template_hooks, uninstall_template_hooks
from shield360.rasp._template import TEMPLATE_ENGINES, detect_template
from shield360.rasp._types import RaspBlockedError

RULE = "code.template_injection"


def hit(source, value, engine):
    found = detect_template(source, [req(value)], engine)
    return found.rule if found else None


# ---- engine table ------------------------------------------------------------------


def test_embedded_engine_table_is_the_contract_table():
    engines = load_json("rules/template-engines.json")["engines"]
    assert TEMPLATE_ENGINES == engines
    assert list(TEMPLATE_ENGINES) == list(engines)
    for name, syntax in engines.items():
        assert list(TEMPLATE_ENGINES[name]) == list(syntax), name


# ---- detector ----------------------------------------------------------------------


def test_structure_overlap_minimum_length_and_single_expression_tokens():
    assert hit("Hello {{ 7 * 7 }}", "{{ 7 * 7 }}", "handlebars") == RULE
    assert hit("<%= 7 * 7 %>", "7 * 7", "ejs") == RULE
    assert hit("p\n  - 7 + 7", "- 7 + 7", "pug") == RULE
    for source, value in (
        ("Hello {{name}}", "name"),
        ('<%= "ordinary prose" %>', "ordinary prose"),
        ("Hello 7 + 7", "7 + 7"),
        ("{{name}}", "absent"),
        ("{{x}}", "x"),
    ):
        assert hit(source, value, "handlebars" if source.startswith("Hello {{") else "ejs") is None


def test_pug_attribute_values_are_expression_regions():
    assert hit('a(href=url + "x") Link', 'url + "x"', "pug") == RULE
    assert hit('a(class="c" href=url)= label + 1', "label + 1", "pug") == RULE
    assert hit("a(href=url) Link", "url", "pug") is None
    assert hit("a(title=\"O'Brien here\") Link", "O'Brien here", "pug") is None
    assert hit("p Hello (see the notes) today", "see the notes", "pug") is None


def test_a_dotted_path_in_a_fixed_template_is_one_reference():
    assert hit("Hello {{user.name}}", "user.name", "handlebars") is None
    assert hit("Hello <%= user.name %>", "user.name", "ejs") is None
    assert hit("Hello {{ user.name }}", "user.name }}", "nunjucks") == RULE


def test_quoted_closing_delimiters_stay_inside_their_token_where_the_engine_lexes_strings():
    assert hit('{{shout "a }} b"}} done', "a }} b", "handlebars") is None
    assert hit('{{ "a }} b" | upper }} done', "a }} b", "nunjucks") is None
    assert hit('p #{"a } b"} done', "a } b", "pug") is None


def test_escaped_mustaches_and_comments_are_literal_text():
    assert hit("Show \\{{name}} literally", "{{name}}", "handlebars") is None
    assert hit("Show \\\\{{name}} live", "{{name}}", "handlebars") == RULE
    assert hit("Hi {# note {{ a + b }} #}", "{{ a + b }}", "nunjucks") is None


def test_shared_engine_table_tags_directives_line_code_attributes_and_pairs_are_regions():
    assert hit("<#if x>${a}</#if>", "x>${a}", "freemarker") == RULE
    assert hit("<#assign x = 7 * 7>", "7 * 7", "freemarker") == RULE
    assert hit("#set($x = 7 * 7)", "7 * 7", "velocity") == RULE
    assert hit("Hi\n% if a + b:\nx", "a + b", "mako") == RULE
    assert hit('<%def name="x()">y</%def>', 'name="x()"', "mako") == RULE
    assert hit('<p th:text="a + b">x</p>', "a + b", "thymeleaf") == RULE
    assert hit("@if($a + $b) y @endif", "$a + $b", "blade") == RULE
    assert hit('{{ printf "%d" 7 }}', 'printf "%d"', "gotemplate") == RULE
    assert hit("Hi {$a + $b}", "$a + $b", "smarty") == RULE
    assert hit("{% raw %}x{% endraw %}{{ a }}", "{% endraw %}{{ a }}", "jinja2") == RULE
    assert detect_template("{{ a }}", [req("{{ a }}")], "unknown") is None


def test_python_engines_literal_text_and_no_wraparound_at_the_edges():
    assert hit("Hello {{ name }}", "{{ name }}", "django") == RULE
    assert hit("{% comment %}{{ a + b }}{% endcomment %}", "{{ a + b }}", "django") is None
    assert hit("Hi ${a + b}", "${a + b}", "mako") == RULE
    assert hit("## a + b\nHi", "a + b", "mako") is None
    assert hit("%% a + b\nHi", "a + b", "mako") is None
    # Index -1 must not read the last character (an escape or word character there changes nothing).
    assert hit("{{name}}\\", "{{name}}", "handlebars") == RULE
    assert hit("@if($a + $b)x", "@if($a + $b)", "blade") == RULE
    assert detect_template("", [req("abc")], "jinja2") is None
    assert detect_template(b"{{ a }}", [req("{{ a }}")], "jinja2") is None


# ---- hooks with stand-in engines ---------------------------------------------------


class _Calls(list):
    inner = None


def _fake_engines():
    calls = _Calls()

    class Environment:
        def from_string(self, source, globals=None, template_class=None):  # pylint: disable=redefined-builtin,unused-argument
            calls.append(("from_string", source))
            return source

    class Template:
        def __new__(cls, source, **options):  # pylint: disable=unused-argument
            return Environment().from_string(source, template_class=cls)

    class DjangoTemplate:
        def __init__(self, template_string, origin=None, name=None, engine=None):  # pylint: disable=unused-argument
            calls.append(("django", template_string))

    class Engine:
        def from_string(self, template_code):
            return DjangoTemplate(template_code, engine=self)

    class MakoTemplate:
        def __init__(self, text=None, filename=None):  # pylint: disable=unused-argument
            calls.append(("mako", text))
            if calls.inner is not None:
                calls.inner()

    mods = {
        "jinja2.environment": {"Environment": Environment, "Template": Template},
        "mako.template": {"Template": MakoTemplate},
        "django.template.base": {"Template": DjangoTemplate},
        "django.template.engine": {"Engine": Engine},
    }
    out = {}
    for name, attrs in mods.items():
        out[name] = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(out[name], key, value)
    return out, calls


@pytest.fixture(name="fakes")
def _fakes():
    modules, calls = _fake_engines()
    saved = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    events = use_engine("block")
    install_template_hooks()
    try:
        yield modules, calls, events
    finally:
        uninstall_template_hooks()
        stop_engine()
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def test_each_engine_entry_point_blocks_tainted_source_before_the_original(fakes):
    modules, calls, events = fakes
    jinja, mako = modules["jinja2.environment"], modules["mako.template"]
    django_base, django_engine = modules["django.template.base"], modules["django.template.engine"]
    for call in (
        lambda: jinja.Template("Hi {{ 7 * 7 }}"),
        lambda: jinja.Environment().from_string("Hi {{ 7 * 7 }}"),
        lambda: mako.Template("Hi ${7 * 7}"),
        lambda: mako.Template(text="Hi ${7 * 7}"),
        lambda: django_base.Template("Hi {{ 7 * 7 }}"),
        lambda: django_engine.Engine().from_string("Hi {{ 7 * 7 }}"),
    ):
        with pytest.raises(RaspBlockedError):
            in_request(["{{ 7 * 7 }}", "${7 * 7}"], call)
    assert not calls
    assert events.sinks() == [
        "jinja2.Template",
        "jinja2.from_string",
        "mako.Template",
        "mako.Template",
        "django.Template",
        "django.from_string",
    ]
    assert set(events.attacks()) == {("code_injection", RULE, "blocked")}


def test_delegation_is_one_check_and_other_inputs_are_still_checked(fakes, monkeypatch):
    modules, calls, _ = fakes
    events = use_engine("monitor")
    seen = []
    real = _template.detect_template

    def spy(source, inputs, engine):
        seen.append([i.value for i in inputs])
        return real(source, inputs, engine)

    monkeypatch.setattr(_template, "detect_template", spy)
    in_request(["{{ 7 * 7 }}"], lambda: modules["jinja2.environment"].Template("Hi {{ 7 * 7 }}"))
    in_request(["{{ 7 * 7 }}"], lambda: modules["django.template.engine"].Engine().from_string("Hi {{ 7 * 7 }}"))
    assert len(events) == 2 and calls == [("from_string", "Hi {{ 7 * 7 }}"), ("django", "Hi {{ 7 * 7 }}")]
    assert seen == [["{{ 7 * 7 }}"], ["{{ 7 * 7 }}"]]

    # A helper that compiles other request data inside an engine call is still checked;
    # input already judged in the enclosing source is not checked again.
    jinja = modules["jinja2.environment"]
    calls.inner = lambda: (jinja.Template("Hello ordinary prose"), jinja.Template("{{ 7 * 7 }}"))
    events.clear()
    seen.clear()
    in_request(["ordinary prose", "{{ 7 * 7 }}"], lambda: modules["mako.template"].Template("Hello ordinary prose"))
    assert seen[0] == ["ordinary prose", "{{ 7 * 7 }}"]
    assert all("ordinary prose" not in values for values in seen[1:])
    assert events.sinks() == ["jinja2.Template"]


def test_fixed_templates_with_input_only_as_data_and_prose_pass(fakes):
    modules, calls, events = fakes
    jinja = modules["jinja2.environment"]
    in_request(["{{ 7 * 7 }}"], lambda: jinja.Template("Hello {{ name }}"))
    in_request(["ordinary prose"], lambda: jinja.Template("Hello ordinary prose"))
    in_request(["name"], lambda: jinja.Template("Hello {{ name }}"))
    assert not events and len(calls) == 3


def test_off_mode_no_context_non_string_sources_and_loader_templates_skip_the_detector(fakes, monkeypatch):
    modules, calls, events = fakes
    seen = []
    monkeypatch.setattr(_template, "detect_template", lambda *a: seen.append(a))
    use_engine("block", attacks={"code_injection": "off"})
    in_request(["{{ 7 * 7 }}"], lambda: modules["jinja2.environment"].Template("Hi {{ 7 * 7 }}"))
    use_engine("block")
    modules["jinja2.environment"].Template("Hi {{ 7 * 7 }}")  # no request context
    in_request(["{{ 7 * 7 }}"], lambda: modules["jinja2.environment"].Environment().from_string(object()))

    class Origin:  # pylint: disable=too-few-public-methods
        loader = object()

    in_request(["{{ 7 * 7 }}"], lambda: modules["django.template.base"].Template("Hi {{ 7 * 7 }}", Origin()))
    assert not seen and not events and len(calls) == 4


def test_original_errors_and_detector_failures(fakes, monkeypatch):
    modules, _, events = fakes

    def broken(*_args):
        raise RuntimeError("detector unavailable")

    monkeypatch.setattr(_template, "detect_template", broken)
    assert in_request(["{{ 7 * 7 }}"], lambda: modules["jinja2.environment"].Template("Hi {{ 7 * 7 }}")) == "Hi {{ 7 * 7 }}"
    assert not events
    with pytest.raises(TypeError):
        in_request(["x"], lambda: modules["mako.template"].Template("a", "b", "c"))


# ---- real engines, when installed --------------------------------------------------


@pytest.fixture(name="engine_on")
def _engine_on():
    events = use_engine("block")
    install_template_hooks()
    try:
        yield events
    finally:
        uninstall_template_hooks()
        stop_engine()


def test_real_jinja2(engine_on):
    jinja2 = pytest.importorskip("jinja2")
    install_template_hooks()
    with pytest.raises(RaspBlockedError):
        in_request(["{{ 7 * 7 }}"], lambda: jinja2.Template("Hi {{ 7 * 7 }}"))
    with pytest.raises(RaspBlockedError):
        in_request(["{{ 7 * 7 }}"], lambda: jinja2.Environment().from_string("Hi {{ 7 * 7 }}"))
    assert engine_on.sinks() == ["jinja2.Template", "jinja2.from_string"]
    out = in_request(["{{ 7 * 7 }}"], lambda: jinja2.Template("Hello {{ name }}").render(name="{{ 7 * 7 }}"))
    assert out == "Hello {{ 7 * 7 }}"
    assert len(engine_on) == 2
    uninstall_template_hooks()
    assert in_request(["{{ 7 * 7 }}"], lambda: jinja2.Template("{{ 7 * 7 }}").render()) == "49"


def test_real_mako(engine_on):
    template = pytest.importorskip("mako.template")
    install_template_hooks()
    with pytest.raises(RaspBlockedError):
        in_request(["${7 * 7}"], lambda: template.Template("Hi ${7 * 7}"))
    with pytest.raises(RaspBlockedError):
        in_request(["${7 * 7}"], lambda: template.Template(text="Hi ${7 * 7}"))
    assert in_request(["${7 * 7}"], lambda: template.Template("Hi ${name}").render(name="${7 * 7}")) == "Hi ${7 * 7}"
    assert engine_on.sinks() == ["mako.Template", "mako.Template"]


def test_real_django(engine_on):
    engine_mod = pytest.importorskip("django.template.engine")
    base = pytest.importorskip("django.template.base")
    context = pytest.importorskip("django.template.context")
    install_template_hooks()
    engine = engine_mod.Engine()
    with pytest.raises(RaspBlockedError):
        in_request(["{{ 7|add:7 }}"], lambda: engine.from_string("Hi {{ 7|add:7 }}"))
    with pytest.raises(RaspBlockedError):
        in_request(["{{ 7|add:7 }}"], lambda: base.Template("Hi {{ 7|add:7 }}", engine=engine))
    assert engine_on.sinks() == ["django.from_string", "django.Template"]
    out = in_request(
        ["{{ 7|add:7 }}"], lambda: engine.from_string("Hi {{ name }}").render(context.Context({"name": "{{ 7|add:7 }}"}))
    )
    assert out == "Hi {{ 7|add:7 }}"
    assert len(engine_on) == 2


def test_review_fixes_literal_whitespace_control_floor_division_and_thymeleaf():
    assert hit("{% raw %}x{%endraw%}{{ 7 * 7 }}", "{{ 7 * 7 }}", "jinja2") == RULE
    assert hit("{% raw %}x{%- endraw -%}{{ 7 * 7 }}", "{{ 7 * 7 }}", "nunjucks") == RULE
    assert hit("{%- raw -%}{{ a + b }}{% endraw %}", "{{ a + b }}", "jinja2") is None
    assert hit("{{ 10 // a + b }}", "a + b", "jinja2") == RULE
    assert hit('<p th:text = "a + b">x</p>', "a + b", "thymeleaf") == RULE
    assert hit("<p>${a + b}</p>", "${a + b}", "thymeleaf") is None


@pytest.fixture(name="code_and_templates")
def _code_and_templates():
    from shield360.rasp._hooks.code import install_code_hooks, uninstall_code_hooks  # pylint: disable=import-outside-toplevel

    events = use_engine("block")
    install_code_hooks()
    install_template_hooks()
    try:
        yield events
    finally:
        uninstall_template_hooks()
        uninstall_code_hooks()
        stop_engine()


def test_real_jinja2_generated_code_skips_judged_input_but_checks_others(code_and_templates):
    jinja2 = pytest.importorskip("jinja2")
    install_template_hooks()
    literal = "from jinja2.runtime import"
    # Literal template text that also appears in Jinja2's generated module code: judged by the template check.
    out = in_request([literal], lambda: jinja2.Environment().from_string(literal + " {{ name }}").render(name="x"))
    assert out == literal + " x"
    assert not code_and_templates

    # An independent input compiled during the render is still checked by the code hook.
    def compiled(value):
        compile(value, "<input>", "eval")
        return "ok"

    env = jinja2.Environment()
    env.globals["compiled"] = compiled
    with pytest.raises(RaspBlockedError):
        in_request(["a.b(c)"], lambda: env.from_string("Hi {{ compiled(code) }}").render(code="a.b(c)"))
    assert code_and_templates.sinks() == ["compile"]

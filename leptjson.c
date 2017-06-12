#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "leptjson.h"
#include <assert.h> /* assert() */
#include <stdlib.h> /* NULL, malloc(), realloc(), free(), strtod() */
#include <math.h> //HUGE_VAL
#include <errno.h>//errno, ERANGE
#include <string.h>//memcpy()

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while (0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define ISWHITESPACE(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\n' || (ch) == '\r')
#define PUTC(c, ch) do { *(char *)lept_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct
{
    const char *json;
    char *stack;
    size_t size, top;
}lept_context;

static void *lept_context_push(lept_context *c, size_t size)
{
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size / 2; // 1.5 * c->size
        c->stack = (char *)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *c, size_t size)
{
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context *c)
{
    const char *p = c->json;
    while (ISWHITESPACE(*p))
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context *c, lept_value *v, const char *literal, lept_type type)
{
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return LEPT_PARSE_INVALID_VALUE;

    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context *c, lept_value *v)
{
    static const int stateTable[][6] =
    {//"1-9", "0", "-", '+', ".", "e/E"
        { 2,   3,   1,  -1,  -1,  -1 },//#0
        { 2,   3,  -1,  -1,  -1,  -1 },//#1
        { 2,   2,  -2,  -2,   4,   6 },//#2
        {-2,  -2,  -2,  -2,   4,  -1 },//#3
        { 5,   5,  -1,  -1,  -1,  -1 },//#4
        { 5,   5,  -2,  -2,  -2,   6 },//#5
        { 8,   8,   7,   7,  -1,  -1 },//#6
        { 8,   8,  -1,  -1,  -1,  -1 },//#7
        { 8,   8,  -2,  -2,  -2,  -2 },//#8
    };
    //valid state is 2, 3, 5, 8
    //error code -1 for invalid numbers,
    //error code -2 for those incorrect inputs which made the flow left state{2, 3, 5, 8}, this mean apart from the current one,
    //the inputs up to now can form a valid number thus can be parsed out patially by function 'stod', i.e. 123-
    //generally speaking, -1 is for LEPT_PARSE_INVALID_VALUE, -2 is for LEPT_PARSE_ROOT_NOT_SINGULAR

    int i, state = 0;
    for (i = 0; c->json[i] != '\0'; i++)
    {
        int input;
        if (ISDIGIT1TO9(c->json[i]))                        input = 0;
        else if (c->json[i] == '0')                         input = 1;
        else if (c->json[i] == '-')                         input = 2;
        else if (c->json[i] == '+')                         input = 3;
        else if (c->json[i] == '.')                         input = 4;
        else if (c->json[i] == 'e' || c->json[i] == 'E')    input = 5;
        else break;//input error, but state maybe valid, i.e. 123a

        if ((state = stateTable[state][input]) < 0)     break;
    }
    
    if (state == 2 || state == 3 || state ==5 || state == 8 || state == -2)
    {
        errno = 0;
        v->n = strtod(c->json, NULL);
        if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
            return LEPT_PARSE_NUMBER_TOO_BIG;

        v->type = LEPT_NUMBER;
        c->json += i;
        return LEPT_PARSE_OK;
    }
    return LEPT_PARSE_INVALID_VALUE;
}

static int lept_parse_string(lept_context *c, lept_value *v)
{
    size_t head = c->top, len;
    const char *p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                len = c->top - head;
                lept_set_string(v, (const char *)lept_context_pop(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\\':
            {
                if (*p == '\"')       PUTC(c, '\"');
                else if (*p == '\\')  PUTC(c, '\\');
                else if (*p == '/' )  PUTC(c, '/');
                else if (*p == 'b')   PUTC(c, '\b');
                else if (*p == 'f')   PUTC(c, '\f');
                else if (*p == 'n')   PUTC(c, '\n');
                else if (*p == 'r')   PUTC(c, '\r');
                else if (*p == 't')   PUTC(c, '\t');
                else {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_ESCAPE;
                }
                p++;
                break;
            }
            case '\0':
                c->top = head;
                return LEPT_PARSE_MISS_QUOTATION_MARK;
            default:
                if ((unsigned char)ch < 0x20)   {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;
                }
                PUTC(c, ch);
        }
    }
}

static int lept_parse_value(lept_context *c, lept_value *v)
{
    switch (*c->json){
        case 't':   return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f':   return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 'n':   return lept_parse_literal(c, v, "null", LEPT_NULL);
        default:    return lept_parse_number(c, v);
        case '"':   return lept_parse_string(c, v);
        case '\0':  return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value *v, const char *json)
{
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK)
    {
        lept_parse_whitespace(&c);
        if (*c.json != '\0')
        {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

void lept_free(lept_value *v)
{
    assert(v != NULL);
    if (v->type == LEPT_STRING)
        free(v->s);
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value *v)
{
    assert(v != NULL);
    return v->type;
}

int lept_get_boolean(const lept_value *v)
{
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value *v, int b)
{
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}

void lept_set_number(lept_value *v, double n)
{
    lept_free(v);//cannot be omitted, because type 'double' share the same space with type 'char *' and size_t
    v->n = n;
    v->type = LEPT_NUMBER;
}

const char *lept_get_string(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s;
}

size_t lept_get_string_length(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->len;
}

void lept_set_string(lept_value *v, const char *s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->s = (char *)malloc(len + 1);
    memcpy(v->s, s, len);
    v->s[len] = '\0';
    v->len = len;
    v->type = LEPT_STRING;
}
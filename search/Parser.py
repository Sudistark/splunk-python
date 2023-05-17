from __future__ import absolute_import
from __future__ import print_function

from builtins import range
from builtins import object

import httplib2

import splunk.safe_lxml_etree as et
import copy
import splunk

import splunk.auth as auth
import splunk.entity as entity
import splunk.rest as rest
import splunk.rest.format
import splunk.util as util

from splunk.search.TransformerUtil import tokenize, searchVToString
from builtins import range




###
### Create
###

def parseSearchToXML(search, hostPath=None, sessionKey=None, parseOnly='t', timeline=None, namespace=None, owner=None):
    """
        Given a valid search string, return the XML from the splunk parsing endpoint that
        represents the search.
    """

    if search == None or len(search) == 0:
        return None

    if not owner: owner = auth.getCurrentUser()['name']

    uri = entity.buildEndpoint('/search/parser', namespace=namespace, owner=owner)
    if hostPath:
        uri = splunk.mergeHostPath(hostPath) + uri

    args = {
        'q'             : search,
        'parse_only'    : parseOnly
    }

    if timeline is not None:
        args['timeline'] = timeline

    serverResponse, serverContent = rest.simpleRequest(uri, getargs=args, sessionKey=sessionKey)
    #print("SERVERCONTENT: %s" % serverContent)
    # normal messages from splunkd are propogated via SplunkdException;
    if 400 <= serverResponse.status < 500:
        root = et.fromstring(serverContent)
        extractedMessages = rest.extractMessages(root)
        for msg in extractedMessages:
            raise splunk.SearchException(msg['text'])

    return serverContent


def parseSearch(search, hostPath=None, sessionKey=None, parseOnly='t', namespace=None, owner=None, timeline=None):
    """
    Given a valid search string, return an object that represents
    the searchs properties
    """

    # parse out the response xml to an object and return it
    return ParsedSearch(parseSearchToXML(search, hostPath, sessionKey, parseOnly, timeline=timeline, namespace=namespace, owner=owner))

###
### Parsed objects
###

class ParsedSearch(object):
    """
    Class to represent a parsed search:
    the properties attribute represents properties of the search as a whole, while
    the clauses attribute is an array of objects, each representing properties of
    individual clauses that make up the search.
    """

    def __init__(self, xml=None) :
        self.properties	= ParsedClause()
        self.clauses	= []

        if xml != None:
            self._parse(xml)

    def __eq__(self, other):
        if not isinstance(other, ParsedSearch) or ( len(self.clauses) != len(other.clauses) ):
            return False

        # iterate over all the clauses and see if they match
        for i in range( 0, len(self.clauses) ):
            if self.clauses[i] != other.clauses[i]:
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.serialize()

    def serialize(self):
        """ Returns the search string this search represents """
        serializedClauses = []
        for clause in self.clauses:
            if clause.isDirty() or clause.rawargs == None:
                clauseStr = clause.serialize()
            else:
                clauseStr = "%s %s" % (clause.command, clause.rawargs)
            serializedClauses.append(clauseStr.strip())

        serialized = ' | '.join(serializedClauses)
        if not serialized.lower().startswith('search'):
            serialized = "| %s" % serialized

        return serialized

    def rawSerialize(self):
        """ Serialize out just the .rawargs of each clause """

        serializedClauses = []
        for clause in self.clauses:
            if not clause.rawargs:
                serializedClauses.append(clause.command)
            else:
                serializedClauses.append("%s %s" % (clause.command, clause.rawargs) )

        rawserialized = ' | '.join(serializedClauses)
        if not rawserialized.lower().startswith('search'):
            rawserialized = "| %s" % rawserialized

        return rawserialized

    def jsonable(self):
        """ Returns the JSONable representation of this search """
        return {
            "search"    :   self.serialize(),
            "clauses"   :   self._gatherJsonables()
        }

    def rawJsonable(self):
        """ Returns the JSONable representation of this search from its rawargs """
        return {
            "search"    :   self.rawSerialize(),
            "clauses"   :   self._gatherJsonables()
        }

    def _gatherJsonables(self):
        clauses = []
        for clause in self.clauses:
            clauses.append(clause.jsonable() )
        return clauses

    def _parse(self, xml):
        """ Does the heavy lifting of converting the XML from splunkd to the object representation """
        if xml != None:
            dom = et.fromstring(xml)

            self.properties._parse(dom.xpath('/response/dict') )

            for n in dom.xpath('/response/list/item'):
                self.clauses.append(ParsedClause(node=n) )
        else:
            return None

    def isDirty(self):
        for clause in self.clauses:
            if clause.isDirty():
                return True
        return False



class ParsedClause(object):
    """
    Class to represent the properties of an individual clause in a search.
    I'm cheating and also using this to hold properties for a whole search.

    This class basically takes a dictionary and turns each key into a
    class property.
    """

    ignoredDefaults = {'readlevel':'2', 'index':'default'}

    def __init__(self, node=None, command=None, args=None) :
        self.properties	= { }
        if node != None:
            self._parse(node)

        if command != None:
            self.properties['command'] = command

            if args != None:
                self.properties['args'] = args
                self.properties['rawargs'] = None

        self.orig = copy.deepcopy(self)

    def isDirty(self):
        return self != self.orig

    def __eq__(self, other):
        # these are default values that are added by the parser. can be safely ignored if not explicitly set by the user

        if not isinstance(other, ParsedClause) or (self.command != other.command):
            return False
        else:
            # handle the case of args is a dictionary
            if isinstance(self.args, dict) and isinstance(other.args, dict):

                for (k, v) in self.args.items():
                    # ignore some keys that are inserted by the parser
                    if ( k in self.ignoredDefaults ) and ( v == self.ignoredDefaults[k] ):
                        continue
                    elif ( not k in other.args ) or ( v != other.args[k] ):
                        return False

            # handle the case when args is single string
            elif isinstance(self.args, str) and isinstance(other.args, str):
                selfTokens = tokenize(self.args)
                otherTokens = tokenize(other.args)

                for token in selfTokens:
                    # ignore defaulted keys
                    if token.find('=') > -1:
                        k, v = token.split('=', 1)
                        if ( k in self.ignoredDefaults ) and ( v == self.ignoredDefaults[k] ):
                            continue

                    if token not in otherTokens:
                        return False

        # if it falls through, we have equality
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.serialize()

    def _chartingSerializer(self, command, args, clauseTokens=None):
        """ special serializer for charting commands """
        if not isinstance(args, dict): raise TypeError("args should be a dict!")

        buffer = [command]
        if clauseTokens:
            buffer.extend(clauseTokens)
        statbuffer = []

        # if we have a 'search' arg, shortcut into this.
        if args.get('search'):
            buffer.append(args.get('search') )
            return ' '.join(buffer)

        if 'xfieldopts' in args:
            v = deClause(args['xfieldopts'])
            buffer.append(' '.join(v))
        statspec = deClause(args.get('stat-specifiers'))
        # gather all the stat functions
        for s in statspec:
            statbuffer.append( s.get('rename') )
        buffer.append( ','.join(statbuffer) )

        # timechart implicitly has a _time xfield, but can have an explicit seriesfield
        # chart needs both xfield and seriesfield defined explicitly
        if command == 'timechart' and args.get('seriesfield'):
            buffer.append( "by %s" % args.get('seriesfield') )
            if 'seriesopts' in args:
                buffer.append(' '.join(deClause(args['seriesopts'])))
            if 'suppressNull' in args:
                buffer.append("usenull=%s" % (not args['suppressNull']))
        elif command == 'chart' and args.get('xfield'):
            chartbuffer = [ args.get('xfield') ]
            if args.get('seriesfield'): chartbuffer.append( args.get('seriesfield') )
            buffer.append ( "by %s" % ",".join(chartbuffer) )
            if 'suppressNull' in args:
                buffer.append("usenull=%s" % (not args['suppressNull']))

        return " ".join(buffer)

    def serialize(self):
        """ Returns the search string this clause represents """
        unsupportedCommands = ['bucket', 'dedup', 'eval', 'kv', 'rex']
        ignoredKeys = ['stat-specifiers', 'xfield', 'seriesfield', 'groupby-fields']



        clauseTokens = []
        command = self.properties['command']

        if command in unsupportedCommands:
            appendThis = self.properties.get('rawargs', None )
            if appendThis == None: return ''
            clauseTokens.append(appendThis.strip() )
            clauseTokens.insert(0, command)
            return ' '.join(clauseTokens)

        if 'args' in self.properties and (self.properties['args'] is not None):
            args = self.properties['args']
            if isinstance(args, dict):

                #
                # TODO: this is a supremely special case switch that is to be
                # removed when stuff gets better.  Because timechart likes to ride the
                # short bus, there are some parameters that must come before any
                # terms, hence this bypass
                #
                timechartPreOps = ["bins", "span"]
                if command.lower() == 'timechart':
                    for k in timechartPreOps:
                        if k in args:
                            clauseTokens.append('%s=%s' % (k, searchVToString(args[k]) ) )
                            ignoredKeys.append(k)

                # if we're a time/chart command, do this special serialization
                # this happens when the charting clauses haven't been washed thru their
                # pre-serialization stuff in un/transform.
                if command in ['timechart', 'chart'] \
                    and 'usenull' not in args and 'useother' not in args:
                    return self._chartingSerializer(command, args, clauseTokens)

                for (k, v) in args.items():
                    # ignore adding any keys of None
                    if v is None: continue

                    if k == 'search':
                        clauseTokens.append( v )
                    elif k == 'fields':
                        clauseTokens.append( ','.join(deClause(v)) ) # space?
                    elif ( k in self.ignoredDefaults ) and ( v == self.ignoredDefaults[k] ):
                        # don't serialize out the ignored defaults
                        continue
                    elif k in ignoredKeys:
                        continue
                    else:
                        # make sure we properly quote strings and leave numerics unquoted
                        clauseTokens.append('%s=%s' % (k, searchVToString(v) ) )
            else:
                clauseTokens.append(args)

        clauseTokens.insert(0, command)

        if clauseTokens != ['search', '*'] and '*' in clauseTokens:
            clauseTokens.remove('*')
        if len(clauseTokens) == 1:
            return clauseTokens[0]

        out = ''
        for clause in clauseTokens:
            if out != '':
                out += ' '
            if isinstance(clause, list):
                out +=  ' '.join(clause).strip()
            else:
                out += clause

        return out

    def jsonable(self):
        """ Returns a JSONable of this clause """
        jsonable_dict = {
            "command":   self.properties['command'],
        }

        if 'args' in self.properties:
            jsonable_dict['args'] = self.properties['args']

        return jsonable_dict

    def _parse(self, node):
        """ Does the heavy lifting of converting the XML from splunkd to the object representation """
        vals = _traverseTree(node)
        # pop off rawargs before normalizing booleans so that 'head 1' doesn't become 'head true'
        if 'rawargs' in vals:
            raw = vals.pop('rawargs')
            util.normalizeBoolean(vals)
            vals['rawargs'] = raw
        else:
            vals = util.normalizeBoolean(vals)
        self.properties = vals
        if 'args' in self.properties:
            #print("args: %s" % self.properties['args'])

            # get rid of some search filter silliness
            if isinstance(self.properties['args'], dict):
                if 'search' in self.properties['args']:
                    self.properties['args']['search'] = self.properties['args']['search']['clauses']

    # property getter/setters
    def _getCommand(self):
        return self.properties['command']

    def _setCommand(self, value):
        self.properties['command'] = value

    def _getArgs(self):
        if 'args' not in self.properties:
            return None
        else:
            return self.properties['args']

    def _setArgs(self, value):
        self.properties['args'] = value

    def _getRawArgs(self):
        if 'rawargs' not in self.properties:
            return None
        else:
            return self.properties['rawargs']

    # setup the .command property
    command = property(
        fget = _getCommand,
        fset = _setCommand,
        fdel = None,
        doc = "Clause command."
    )

    # setup the .args property
    args = property(
        fget = _getArgs,
        fset = _setArgs,
        fdel = None,
        doc = "Clause arguments."
    )

    rawargs = property(
        fset = None,
        fget = _getRawArgs,
        fdel = None,
        doc = "Raw Clause arguments."
    )

###
### Utils for traversing the xml that we get back from
### /services/search/parser
###

def _traverseTree(node):
    """
    Traverse an elementtree and convert it to a dictionary
    """
    bigDict = {}
    if len(node) > 0:
        for child in node:
            if child.tag == 'dict':
                bigDict  = _traverseDict(child)
            elif child.tag == 'list':
                bigDict['clauses'] = _traverseList(child)
                #bigDict= _traverseList(child)
            elif child.tag == 'item':
                bigDict[child.tag] = _traverseItem(child)
            elif child.tag == 'key':
                bigDict[child.tag] = _traverseKey(child)

    return bigDict

def _traverseDict(node):
    outDict = {}
    for child in node:
        if len(child) > 0:
            name = child.get('name')
            if name == None:
                name = child.tag
            outDict[name] = _traverseTree(child)
        elif child.text:
            outDict[child.get('name')] = child.text
#       else:
#           outDict[child.get('name')] = None
    return outDict

def _traverseList(node):
    outList = []
    for child in node:
        if len(child) > 0:
            outList.append(_traverseTree(child) )
        elif child.text:
            outList.append(child.text)
        else:
            outList.append(None)
    return outList

def _traverseItem(node):
    for child in node:
        return _traverseDict(child)

def _traverseKey(node):
    outKey = ()
    for child in node:
        if len(child) > 0:
            outkey = (child.tag, _traverseTree(child) )
        elif child.text:
            outKey = (child.get('name'), child.text)
        else:
            outKey = (None, None)
    return outKey

# returns value of 'clause' if dict val
def deClause(val):
    if isinstance(val, dict) and 'clauses' in val:
        val = val['clauses']
    return val

# Unittests
import unittest
import json
import splunk.search.TransformerUtil as tu

def normalizeListArgs(val):
    if isinstance(val, list):
        return ' '.join(val).strip()
    elif isinstance(val, str):
        return val.strip()
    return val

from splunk.util import pytest_mark_skip_conditional
@pytest_mark_skip_conditional(reason="SPL-175665: Probably a regression or functional test now")
class TestParse(unittest.TestCase):
    def setUp(self):
        self._sessionKey = auth.getSessionKey('admin', 'changeme')
        self._hostPath   = splunk.mergeHostPath()

    # searches
    q = {
        'single': "search foo bar baz",
        'two': "search quux | diff position1=1 position2=2",
        'quotes': 'search twikiuser="ivan" | diff position1=1 position2=2',
    }

    def testCreateClause(self):
        """ Test the creation of new clause objects """

        clause1 = ParsedClause()
        clause1.command = "search"
        clause1.args = "foo"
        self.assertEqual(clause1.serialize(), "search foo")

        # python dicts (the structure in which args are stored in the ParsedClause class)
        # no longer maintain determinate ordering.
        # therefore, the output of this test can be either
        #   search index="_audit" foo bar baz, or
        #   search foo bar baz index="_audit"
        # both are identical searches
        clause2 = ParsedClause()
        clause2.command = "search"
        clause2.args = {'index' : '_audit', 'search' : "foo bar baz"}
        clause2String = clause2.serialize()
        self.assertTrue(clause2String == 'search index="_audit" foo bar baz' or clause2String == 'search foo bar baz index="_audit"')

        clause3 = ParsedClause(command="search", args="quux")
        self.assertEqual(clause3.serialize(), 'search quux')

        clause4 = ParsedClause(command="loglady")
        self.assertEqual(clause4.serialize(), 'loglady')

    def testEqualsOperatorClause(self):
        """ Test the equals operator in ParsedClause """

        # two clauses, including kv's that should be ignored in the compare, string case
        clause1 = ParsedClause()
        clause1.command = "search"
        clause1.args = "foo readlevel=2"
        clause2 = ParsedClause()
        clause2.command = "search"
        clause2.args = "foo index=default"
        self.assertTrue( clause1 == clause2 )

        # two clauses, including kv's that should be ignored in the compare, dict case
        clause3 = ParsedClause()
        clause3.command = "search"
        clause3.args = {"index":"_internal", "user":"john"}
        clause4 = ParsedClause()
        clause4.command = "search"
        clause4.args = {"index":"_internal", "user":"john", "readlevel":"2"}
        self.assertTrue( clause3 == clause4 )

        # two clauses, including kv's that should be not ignored in the compare, string case
        clause5 = ParsedClause()
        clause5.command = "search"
        clause5.args = "foo readlevel=11"
        clause6 = ParsedClause()
        clause6.command = "search"
        clause6.args = "foo index=default"
        self.assertFalse( clause5 == clause6 )

        # test indiv clauses pulled out of ParsedSearch
        search1 = parseSearch(self.q['two'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        search2 = parseSearch(self.q['two'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertTrue( search1.clauses[1] == search2.clauses[1] )

    def testEqualsOperatorSearch(self):
        """ Test the equals operator in ParsedSearch """

        ps1 = parseSearch(self.q['single'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        ps2 = parseSearch(self.q['single'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertTrue( ps1 == ps2 )

        ps3 = parseSearch(self.q['single'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        ps4 = parseSearch(self.q['two'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertTrue( ps3 != ps4 )

    def testParseOneClause(self):
        """ Test the parsing of a single clause search """

        ps = parseSearch(self.q['single'], hostPath=self._hostPath, sessionKey=self._sessionKey)

        self.assertEqual(len(ps.clauses), 1)
        self.assertEqual(ps.clauses[0].command, 'search')
        self.assertEqual(ps.clauses[0].serialize(), 'search foo bar baz')
        self.assertTrue(ps.clauses[0].properties['streamType'] == 'SP_STREAM')

    def testParseTwoClause(self):
        """ Test the parsing of a single clause search """

        ps = parseSearch(self.q['two'], hostPath=self._hostPath, sessionKey=self._sessionKey)

        self.assertEqual(len(ps.clauses), 2)
        self.assertEqual(ps.clauses[0].command, 'search')
        self.assertEqual(ps.clauses[1].command, 'diff')
        self.assertEqual(normalizeListArgs(ps.clauses[0].args['search']), 'quux')
        self.assertEqual(normalizeListArgs(ps.clauses[1].args), 'position1=1 position2=2')
        print("PROPS: %s" % ps.clauses[1].properties)
        self.assertEqual(ps.clauses[1].properties['streamType'], 'SP_EVENTS')


    def testSerialize(self):
        """ Test search serialization/tostring"""

        ps = parseSearch(self.q['single'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertEqual(str(ps), self.q['single'])

        ps = parseSearch(self.q['two'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertEqual(str(ps), self.q['two'])

        ps = parseSearch(self.q['quotes'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertEqual(str(ps), self.q['quotes'])

        indexSearch = 'search index="_audit"'
        ps = parseSearch(indexSearch, hostPath=self._hostPath, sessionKey=self._sessionKey)
        self.assertEqual(str(ps), indexSearch)

    def testJsonable(self):
        """ Test JSONable """
        ps = parseSearch(self.q['single'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        print("\n\t%s" % json.dumps(ps.jsonable()))

        ps = parseSearch(self.q['quotes'], hostPath=self._hostPath, sessionKey=self._sessionKey)
        print("\t%s" % json.dumps(ps.jsonable()))

    def test_chartSerializer(self):
        """ Test chart serialization """
        pc = ParsedClause()

        cases = {
            'chart sum(events) by hello,world':
            {'xfield': 'hello', 'stat-specifiers': [{'function': 'sum', 'field': 'events', 'rename': 'sum(events)'}], 'seriesfield': 'world'},

            'chart sum(events),count by hello,world':
            {'xfield': 'hello','seriesfield': 'world',
                'stat-specifiers': [
                {'function': 'sum', 'field': 'events', 'rename': 'sum(events)'},
                {'function': 'count', 'rename': 'count'}
                ]
            },

            'timechart sum(events) by world':
            {'xfield': '_time', 'stat-specifiers': [{'function': 'sum', 'field': 'events', 'rename': 'sum(events)'}], 'seriesfield': 'world'},

            'timechart sum(events),count by hello':
            {'xfield': '_time','seriesfield': 'hello',
                'stat-specifiers': [
                {'function': 'sum', 'field': 'events', 'rename': 'sum(events)'},
                {'function': 'count', 'rename': 'count'}
                ]
            },

            'timechart span="1d" sum(events) by world':
            {'xfield': '_time', 'stat-specifiers': [{'function': 'sum', 'field': 'events', 'rename': 'sum(events)'}], 'seriesfield': 'world', 'span':'1d'},

            'timechart bins=5 sum(events) by world':
            {'xfield': '_time', 'stat-specifiers': [{'function': 'sum', 'field': 'events', 'rename': 'sum(events)'}], 'seriesfield': 'world', 'bins':5 },
        }
        for k, v in cases.items():
            command = k.split()[0]
            out = str(ParsedClause(None, command, v))  #out = pc._chartingSerializer(command, v)
            if out != k:
                print("\n\nINPUT:  %s" % v)
                print("GOAL:   %s" % k)
                print("OUTPUT: %s" % out)
                self.assertEqual( k, out)

### Moved these Unit tests TransformerUtil.py due to cyclic dependency
@pytest_mark_skip_conditional(reason="SPL-175665: Probably a regression or functional test now")
class TestTransformUtil(unittest.TestCase):
    def setUp(self):
        self._sessionKey = splunk.auth.getSessionKey('admin', 'changeme')
        self._hostPath   = splunk.mergeHostPath()

    def testHasTerms(self):
        """ Are terms found correctly in search strings? """

        searchString = 'search userid=6 username="nick" owner=ivan login'
        ps = parseSearch(searchString, hostPath=self._hostPath, sessionKey=self._sessionKey)

        sc = tu.getClauseWithCommand(ps, "search")

        self.assertTrue( tu.hasTerm(sc, "login") )
        self.assertTrue( tu.hasTerm(sc, {"username":"nick"}) )
        self.assertTrue( tu.hasTerm(sc, {"userid":6}) )

        self.assertTrue( tu.hasTerm(sc, 'username="nick"') )
        self.assertTrue( tu.hasTerm(sc, 'username=nick') )
        self.assertTrue( tu.hasTerm(sc, 'owner="ivan"') )
        self.assertTrue( tu.hasTerm(sc, 'owner=ivan') )
        self.assertTrue( tu.hasTerm(sc, "userid=6") )

        self.assertTrue( not tu.hasTerm(sc, "shouldNotBeHere") )
        self.assertTrue( not tu.hasTerm(sc, {"username":"ivan"}) )
        self.assertTrue( not tu.hasTerm(sc, {"userid":7}) )

    def testRemoveTerms(self):
        """ Are search terms correctly removed from search strings? """

        searchString = 'search loglevel=7 userid=6 username="nick" owner=ivan target="mars" destination=home login'
        ps = parseSearch(searchString, hostPath=self._hostPath, sessionKey=self._sessionKey)

        sc = tu.getClauseWithCommand(ps, "search")

        tu.removeTerm(sc, "login")
        self.assertTrue(sc.serialize().find("login") == -1 )

        tu.removeTerm(sc, {"username" : "nick"} )
        self.assertTrue(sc.serialize().find('username="nick"') == -1 )

        tu.removeTerm(sc, {"owner" : "ivan"} )
        self.assertTrue(sc.serialize().find('owner=ivan') == -1 )

        tu.removeTerm(sc, {"userid" : 6} )
        self.assertTrue(sc.serialize().find('userid=6') == -1 )

        tu.removeTerm(sc, 'target=mars' )
        tu.removeTerm(sc, 'destination="home"' )

        tu.removeTerm(sc, "loglevel=7")
        self.assertTrue(sc.serialize().find('loglevel=7') == -1 )

        # ELVIS print(sc.serialize())
        self.assertTrue( sc.serialize() == 'search *' )


        # SPL-32258
        searchString = 'search index=_internal sourcetype=splunkd OR sourcetype=searches'
        ps = parseSearch(searchString, hostPath=self._hostPath, sessionKey=self._sessionKey)
        sc = tu.getClauseWithCommand(ps, "search")

        tu.removeTerm(sc, {'sourcetype': 'searches'})
        self.assertTrue(sc, 'index="_internal" sourcetype="splunkd"')
        
        searchString = 'search index=_internal sourcetype=splunkd OR sourcetype=searches'
        ps = parseSearch(searchString, hostPath=self._hostPath, sessionKey=self._sessionKey)
        sc = tu.getClauseWithCommand(ps, "search")

        tu.removeTerm(sc, {'sourcetype': 'splunkd'})
        self.assertTrue(sc, 'index="_internal" sourcetype="searches"')

    def testRemoveTermsEscaped(self):
        '''
        Verify remove term behavior when presented with terms that contain
        escape character
        '''

        beforeSearchString = r'search this \\that foo'
        parser = parseSearch(beforeSearchString, hostPath=self._hostPath, sessionKey=self._sessionKey)
        searchClause = tu.getClauseWithCommand(parser, 'search')
        tu.removeTerm(searchClause, r'\\that')
        self.assertEqual(searchClause.serialize(), 'search this foo')

        beforeSearchString = r'search this \that foo'
        parser = parseSearch(beforeSearchString, hostPath=self._hostPath, sessionKey=self._sessionKey)
        searchClause = tu.getClauseWithCommand(parser, 'search')
        tu.removeTerm(searchClause, r'\that')
        self.assertEqual(searchClause.serialize(), 'search this foo')



    def testTokenize(self):
        """ Are search strings correctly tokenized? """

        tokenTests = [
            ( 'johnsmith',              ['johnsmith'] ),
            ( 'john smith',             ['john', 'smith'] ),
            ( 'x="y z"',                ['x="y z"'] ),
            ( 'user=Main.JohnSmith',    ['user=Main.JohnSmith'] ),
            ( 'superman "Lex Luther"',  ['superman', '"Lex Luther"'] ),
            ( 'sourcetype=bar',         ['sourcetype=bar'] ),
            ( 'sourcetype::bar',        ['sourcetype=bar'] ),
            ( '( sourcetype=bar )',        ['sourcetype=bar'] ),
            ( 'source="/var/log/*"',    ['source="/var/log/*"'] ),
            ( 'x=p',                    ['x=p'] ),
            ( 'x="p"',                  ['x="p"'] ),
            ( 'NOT x',                    ['NOT x'] ),
            ( 'x NOT y',                    ['x', 'NOT y'] ),
            ( 'x NOT y z',                    ['x', 'NOT y', 'z'] ),
            ( '(toBe OR notToBe) question',    ['(toBe OR notToBe)', 'question'] ),
            ( 'toBe OR notToBe) question',     ['toBe', 'OR', 'notToBe)', 'question'] ),
            ( 'toBe OR notToBe) ) question',   ['toBe', 'OR', 'notToBe)', ')', 'question'] ),
            ( 'toBe OR notToBe)) question',    ['toBe', 'OR', 'notToBe))', 'question'] ),
            ( '((toBe OR notToBe)) question',  ['((toBe OR notToBe))', 'question'] ),
            ( '((toBe OR notToBe question',    ['((toBe OR notToBe question'] ),
            ( '(toBe OR (notToBe)) question',  ['(toBe OR (notToBe))', 'question'] ),
            ( '(toBe (OR (not)ToBe)) question', ['(toBe (OR (not)ToBe))', 'question'] ),
            ( 'error OR failed OR severe OR ( sourcetype=access_* ( 404 OR 500 OR 503 ) ) starthoursago::24',\
                ['error', 'OR', 'failed', 'OR', 'severe', 'OR', '( sourcetype=access_* ( 404 OR 500 OR 503 ) )', 'starthoursago::24']),
            ( 'error OR failed OR severe OR ( sourcetype="access_*" ( 404 OR 500 OR 503 ) ) starthoursago::24',\
                ['error', 'OR', 'failed', 'OR', 'severe', 'OR', '( sourcetype="access_*" ( 404 OR 500 OR 503 ) )', 'starthoursago::24']),
            ('search foo [search bar | top host | format]', ['search', 'foo', '[search bar | top host | format]']),
            ('search foo [search bar [search wunderbar] | top host | format]', ['search', 'foo', '[search bar [search wunderbar] | top host | format]']),
            ('search "["', ['search', '"["']),
            ('search "]"', ['search', '"]"']),
            ('search "[[]"', ['search', '"[[]"']),
            ('search "("', ['search', '"("']),
            ('search "(["', ['search', '"(["']),
            ('search "]"', ['search', '"]"']),

            ('search this [search "]"]', ['search', 'this', '[search "]"]']),
            ('search this (that OR ")")', ['search', 'this', '(that OR ")")']),
        ]

        for test in tokenTests:
            self.assertEqual( tokenize(test[0]), test[1] )

    def testStringToKV(self):
        """ Are terms correctly tokenized in KV pairs? """

        self.assertEqual(tu.stringToSearchKV( "index=_audit login" ), {"index":"_audit", "search":"login"} )

    def testEqualStringTerms(self):
        """ Are quotes in kv pairs ignored? """
        
        self.assertTrue( tu._equalKVStringTerms('hello=world', 'hello=world') )
        self.assertTrue( tu._equalKVStringTerms('hello=world', 'hello="world"') )
        self.assertTrue( tu._equalKVStringTerms("hello='world'", 'hello="world"') )
        self.assertTrue( tu._equalKVStringTerms("hello='world'", 'hello=world') )

        self.assertFalse( tu._equalKVStringTerms("hello='world'", 'hello=wxrld') )

    def testKToString(self):
        """ Are K fields correctly quoted when needed? """

        self.assertEqual(tu.searchKToString("johnsmith" ), 'johnsmith' )
        self.assertEqual(tu.searchKToString("john smith" ), '"john smith"' )
        self.assertEqual(tu.searchKToString('boo'), 'boo' )

    def testKVToString(self):
        """ Are KV pairs correctly merged into search string terms? """

        self.assertEqual(tu.searchVToString("johnsmith" ), '"johnsmith"' )
        self.assertEqual(tu.searchVToString("john smith" ), '"john smith"' )
        self.assertEqual(tu.searchVToString( 26 ), '26' )
        self.assertEqual(tu.searchVToString( '26' ), '"26"' )
        self.assertEqual(tu.searchVToString('"6"'), '"6"' )
        self.assertEqual(tu.searchVToString('"boo"'), '"boo"' )
        self.assertEqual(tu.searchVToString('boo'), '"boo"' )
        
    def testUnfilter(self):
        """ Are the search terms correctly parsed out of search filter wrappers? """

        self.assertEqual( tu.unfilterize( "( index=_audit login ) ( ( * ) )" ), "index=_audit login")
        self.assertEqual( tu.unfilterize( "  ( index=_audit login ) ( ( * ) )" ), "index=_audit login")
        self.assertEqual( tu.unfilterize( "  ( index=_audit login ) ( ( * ) )  " ), "index=_audit login")

if __name__ == "__main__":
    # Execute test suite.
    pass
#    unittest.main()
#    transformSuite = unittest.TestLoader().loadTestsFromTestCase(TestTransformUtil)
#    parseSuite = unittest.TestLoader().loadTestsFromTestCase(TestParse)
#    unittest.TextTestRunner(verbosity=3).run(unittest.TestSuite([parseSuite, transformSuite]))

from ..dispersy import SignatureRequestCache
from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestSignature(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_no_response_from_node(self):
        """
        SELF will request a signature from NODE.  Node will ignore this request and SELF should get
        a timeout on the signature request after a few seconds.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        container = {"timeout": 0}

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()
        yield 0.555

        logger.debug("SELF requests NODE to double sign")

        def on_response(cache, response, modified):
            self.assertIsInstance(cache, SignatureRequestCache)
            self.assertIsNone(response)
            self.assertFalse(modified)
            logger.debug("timeout occurred")
            container["timeout"] += 1
            return False

        community.create_double_signed_text("Allow=<does not reach this point>, CounterPropose=<does not reach this point>", node.candidate,
                                            self._dispersy.get_member(node.my_member.public_key), on_response, (),
                                            None, (), 3.0)
        yield 0.11

        logger.debug("NODE receives dispersy-signature-request message")
        node.receive_message(message_names=[u"dispersy-signature-request"])
        # do not send a response

        # should timeout
        wait = 4
        for counter in range(wait):
            logger.debug("waiting... %d", wait - counter)
            yield 1.0
        yield 0.11

        logger.debug("SELF must have timed out by now")
        self.assertEqual(container["timeout"], 1)

    def test_response_from_node_True(self):
        return self.response_from_node(True)
    def test_response_from_node_False(self):
        return self.response_from_node(False)

    @call_on_dispersy_thread
    def response_from_node(self, accept_response):
        """
        SELF will request a signature from NODE.  SELF will receive the signature and produce a
        double signed message.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        container = {"response": 0, "success":0}

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("SELF requests NODE to double sign")

        def on_response(cache, response, modified, *args):
            self.assertIsInstance(cache, SignatureRequestCache)
            self.assertEqual(response.name, u"double-signed-text")
            self.assertEqual(args, ("param-test-1",))
            self.assertEqual(container["response"], 0)
            self.assertFalse(response.authentication.is_signed)
            self.assertFalse(modified)
            container["response"] += 1
            # when we return True the on_success should be called with the fully signed message
            return accept_response

        def on_success(cache, response, *args):
            self.assertIsInstance(cache, SignatureRequestCache)
            self.assertEqual(response.name, u"double-signed-text")
            self.assertEqual(args, ("param-test-2",))
            self.assertEqual(container["success"], 0)
            self.assertTrue(response.authentication.is_signed)
            container["success"] += 1

        cache = community.create_double_signed_text("Allow=<does not matter>, CounterPropose=<does not matter>", node.candidate,
                                                    self._dispersy.get_member(node.my_member.public_key),
                                                    on_response, ("param-test-1",),
                                                    on_success, ("param-test-2",), 3.0)
        self.assertEqual(cache.request.name, u"dispersy-signature-request")
        self.assertEqual(cache.request.payload.message.name, u"double-signed-text")
        self.assertEqual([signature for signature, _ in cache.request.payload.message.authentication.signed_members], ["", ""])
        yield 0.11

        logger.debug("NODE receives dispersy-signature-request message from SELF")
        candidate, message = node.receive_message(message_names=[u"dispersy-signature-request"])
        submsg = message.payload.message
        self.assertEqual([signature for signature, _ in submsg.authentication.signed_members], ["", ""])
        second_signature_offset = len(submsg.packet) - community.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        self.assertEqual(submsg.packet[first_signature_offset:second_signature_offset], "\x00" * community.my_member.signature_length,
                         "The first signature MUST BE \\x00's.  None of the signatures are set when performing the request")
        self.assertEqual(submsg.packet[second_signature_offset:], "\x00" * node.my_member.signature_length,
                         "The second signature MUST BE \\x00's.  None of the signatures are set when performing the request")

        logger.debug("NODE adds its own signature to the message proposed by SELF")
        signature = node.my_member.sign(submsg.packet, length=first_signature_offset)
        submsg.authentication.set_signature(node.my_member, signature, sign=False)
        self.assertEqual(submsg.packet[first_signature_offset:second_signature_offset], "\x00" * community.my_member.signature_length,
                         "The first signature MUST BE \\x00's.  NODE can not set the signature of SELF")
        self.assertEqual(submsg.packet[second_signature_offset:], signature, "The second signature was just set by NODE")

        logger.debug("NODE sends dispersy-signature-response message to SELF")
        identifier = message.payload.identifier
        global_time = community.global_time
        message = node.create_dispersy_signature_response(identifier, submsg, global_time, candidate)
        self.assertEqual(message.payload.message.packet[first_signature_offset:second_signature_offset], "\x00" * community.my_member.signature_length,
                         "The first signature MUST BE \\x00's.  NODE can not set the signature of SELF")
        self.assertEqual(message.payload.message.packet[second_signature_offset:], signature, "The second signature was just set by NODE")
        node.give_message(message)
        yield 0.11

        self.assertEqual(container["response"], 1)
        self.assertEqual(container["success"], 1 if accept_response else 0)

    def test_response_from_self_counter(self):
        return self.response_from_self(True)
    def test_response_from_self_no_counter(self):
        return self.response_from_self(False)

    @call_on_dispersy_thread
    def response_from_self(self, counter_propose):
        """
        NODE will request a signature from SELF.  SELF will receive the request and respond with a
        signature response.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("NODE requests SELF to double sign")
        identifier = 12345
        global_time = 10
        submsg = node.create_double_signed_text(community.my_member,
                                                "Allow=True, CounterPropose=%s" % counter_propose,
                                                global_time,
                                                sign=False)
        node.give_message(node.create_dispersy_signature_request(identifier, submsg, global_time))
        self.assertEqual([signature for signature, _ in submsg.authentication.signed_members], ["", ""])
        yield 0.11

        logger.debug("Node waits for SELF to provide a signature response")
        _, message = node.receive_message(message_names=[u"dispersy-signature-response"])
        self.assertEqual(message.payload.identifier, identifier)

        # the response message should:
        # 1. everything up to the first signature must be the same
        second_signature_offset = len(submsg.packet) - community.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        counter_second_signature_offset = len(message.payload.message.packet) - community.my_member.signature_length
        counter_first_signature_offset = counter_second_signature_offset - node.my_member.signature_length
        if not counter_propose:
            self.assertEqual(message.payload.message.packet[:counter_first_signature_offset], submsg.packet[:first_signature_offset])

        # 2. the first signature must be zero's (this is NODE's signature and hasn't been set yet)
        self.assertEqual(message.payload.message.packet[counter_first_signature_offset:counter_second_signature_offset],
                         "\x00" * node.my_member.signature_length)
        self.assertEqual(message.payload.message.authentication.signed_members[0][0], "")

        # 3. the second signature must be set and valid
        self.assertNotEqual(message.payload.message.packet[counter_second_signature_offset:],
                            "\x00" * community.my_member.signature_length)
        self.assertNotEqual(message.payload.message.authentication.signed_members[1][0], "")
        self.assertTrue(community.my_member.verify(message.payload.message.packet[:counter_first_signature_offset],
                                                   message.payload.message.packet[counter_second_signature_offset:]))
        self.assertTrue(community.my_member.verify(message.payload.message.packet[:counter_first_signature_offset],
                                                   message.payload.message.authentication.signed_members[1][0]))

    @call_on_dispersy_thread
    def test_no_response_from_self(self):
        """
        NODE will request a signature from SELF.  SELF will ignore this request and NODE should not
        get any signature response.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("NODE requests SELF to double sign")
        identifier = 12345
        global_time = 10
        submsg = node.create_double_signed_text(community.my_member, "Allow=False, CounterPropose=True", global_time, sign=False)
        node.give_message(node.create_dispersy_signature_request(identifier, submsg, global_time))
        yield 0.11

        logger.debug("Node waits for SELF to provide a signature response")
        wait = 4
        for counter in range(wait):
            logger.debug("waiting... %d", wait - counter)
            yield 1.0
            messages = node.receive_messages(message_names=[u"dispersy-signature-response"])
            self.assertEqual(messages, [])

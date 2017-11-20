import functools
import numpy as np
import tensorflow as tf

def scope_decorator(function):
    """
    Decorator that handles graph construction and variable scoping
    """

    name = function.__name__
    attribute = '_cache_' + name

    @property
    @functools.wraps(function)
    def decorator(self):
        if not hasattr(self,attribute):
            with tf.variable_scope(name):
                setattr(self,attribute,function(self))
        return getattr(self,attribute)

    return decorator

def weight_variable(shape, stddev):
    """
    Creates a variable tensor with a shape defined by the input
    Inputs:
        shape: list containing dimensionality of the desired output
        stddev: standard deviation to initialize with
    """
    initial = tf.truncated_normal(shape, stddev=stddev)
    return tf.Variable(initial)

def bias_variable(shape, value=0.1):
    """
    Creates a variable tensor with dimensionality defined by the input and
    initializes it to a constant
    Inputs:
        shape: list containing dimensionality of the desired output
        value: float specifying the initial value of the variable
    """
    initial = tf.constant(value, shape=shape)
    return tf.Variable(initial)

class AbnormalDetector:
    def __init__(
                    self, 
                    packet_embedding_size=100, 
                    session_embedding_size=100,
                    hidden_size=100,
                    num_chars=16,
                    num_labels=32,
                    attn_size=10
                ):
        """
        Initializes the model
        """

        self.packet_embedding_size = packet_embedding_size
        self.session_embedding_size = session_embedding_size
        self.hidden_size = hidden_size
        self.num_chars = num_chars 
        self.num_labels = num_labels
        self.attn_size = attn_size
        
        self.graph = tf.Graph()
        with self.graph.as_default():

            # Placeholder tensor for the input sessions
            self.X = tf.placeholder("float", [None, None, None, self.num_chars])
            
            # Placeholder tensor for the input representations
            self.R = tf.placeholder("float", [None,self.num_labels])
            
            # Placeholder tensor for the labels/targets
            self.Y = tf.placeholder("float", [None, 1])

            # Placeholder for dropout amount
            self.keep_prob = tf.placeholder(tf.float32)
            
            # Model methods
            self.network
            self.cost
            self.optimizer
            self.get_output
            
            # Saver
            self.saver = tf.train.Saver()


        # Create a session to run this graph
        self.sess = tf.Session(graph = self.graph)

    def __del__(self):
        """
        Close the session when the model is deleted
        """

        self.sess.close()

    def initialize(self):
        """
        Initialize variables in the graph
        """

        with self.graph.as_default():
            self.sess.run(tf.global_variables_initializer())
            

    @scope_decorator
    def network(self):
        """
        Construct the network used for classifying sessions
        """

        # Get the shape of the input
        shape = tf.shape(self.X)

        # Reshape the packet number into the batch to embed each packet
        # separately
        X_reshaped = tf.reshape(self.X,
[shape[0]*shape[1],shape[2],self.num_chars])
        
        # Embed the packets with a BLSTM  with attention
        with tf.variable_scope('packet_rnn', reuse=None):
            # Attend over the input
            packet_cell_f = tf.contrib.rnn.BasicLSTMCell(
                                                 self.packet_embedding_size//2,
                                                 activation=tf.tanh
                                                        )
            packet_cell_b = tf.contrib.rnn.BasicLSTMCell(
                                                 self.packet_embedding_size//2,
                                                 activation=tf.tanh
                                                        )
            packet_attn_cell_f = tf.contrib.rnn.AttentionCellWrapper(
                                                    packet_cell_f,
                                                    attn_length=self.attn_size,
                                                    state_is_tuple=True
                                                                   )
            packet_attn_cell_b = tf.contrib.rnn.AttentionCellWrapper(
                                                    packet_cell_b,
                                                    attn_length=self.attn_size,
                                                    state_is_tuple=True
                                                                    )
            packet_vectors, packet_states = tf.nn.bidirectional_dynamic_rnn(
                                                            packet_attn_cell_f,
                                                            packet_attn_cell_b,
                                                            X_reshaped,
                                                            dtype=tf.float32
                                                                           )

        packet_vectors_f = packet_vectors[0][:,-1,:]
        packet_vectors_b = packet_vectors[1][:,-1,:]
        packet_vectors = tf.concat([packet_vectors_f, packet_vectors_b],1)
        # Reshape this to recover the session dimension
        sessions = tf.reshape(packet_vectors,
                                [shape[0],shape[1],self.packet_embedding_size])

        # Embed the sessions with a BLSTM with attention
        with tf.variable_scope('session_rnn', reuse=None):
            # Attend over the packets
            session_cell_f = tf.contrib.rnn.BasicLSTMCell(
                                                self.session_embedding_size//2,
                                                activation=tf.tanh
                                                         )
            session_cell_b = tf.contrib.rnn.BasicLSTMCell(
                                                self.session_embedding_size//2,
                                                activation=tf.tanh
                                                         )
            session_attn_cell_f = tf.contrib.rnn.AttentionCellWrapper(
                                                    session_cell_f,
                                                    attn_length=self.attn_size,
                                                    state_is_tuple=True
                                                                     )
            session_attn_cell_b = tf.contrib.rnn.AttentionCellWrapper(
                                                    session_cell_b,
                                                    attn_length=self.attn_size,
                                                    state_is_tuple=True
                                                                     )
            session_vectors, session_states = tf.nn.bidirectional_dynamic_rnn(
                                                    session_attn_cell_f,
                                                    session_attn_cell_b,
                                                    sessions,
                                                    dtype=tf.float32
                                                                           )

        session_vectors_f = session_vectors[0][:,-1,:]
        session_vectors_b = session_vectors[1][:,-1,:]
        session_vectors = tf.concat([session_vectors_f, session_vectors_b],1)

        # Concatenate the session vectors and the representation vectors
        combined_vectors = tf.concat([session_vectors, self.R],1)

        # Pass the concatenated vectors through a feedforward layer
        concat_size = self.session_embedding_size+self.num_labels
        std_dev = np.sqrt(2)/np.sqrt(concat_size+self.hidden_size)
        weights_1 = weight_variable([concat_size,self.hidden_size], std_dev)
        biases_1 = bias_variable([self.hidden_size], value=0.0)
        layer_1 = tf.matmul(combined_vectors,weights_1) + biases_1
        layer_1 = tf.nn.tanh(layer_1)

        # Pass this through a second dense layer to get the output
        std_dev = np.sqrt(2)/np.sqrt(self.hidden_size + 1)
        weights_2 = weight_variable([self.hidden_size,1], std_dev)
        biases_2 = bias_variable([1], value=0.0)
        output = tf.matmul(layer_1,weights_2) + biases_2

        probs = tf.nn.sigmoid(output)
        return output, probs

    @scope_decorator
    def cost(self):
        """
        Binary cross entropy cost
        """
        output, _ = self.network
        cost = tf.losses.sigmoid_cross_entropy(self.Y, output)
        return cost

    @scope_decorator
    def optimizer(self):
        """
        Constructs the optimizer op used to train the network.  Use gradient
        clipping.
        """
        opt = tf.train.AdamOptimizer()
        gradients, variables = zip(*opt.compute_gradients(self.cost))
        gradients, _ = tf.clip_by_global_norm(gradients, 1.0)
        return opt.apply_gradients(zip(gradients, variables))

    def save(self, path):
        """
        Saves the model to the specified path.
        """
        self.saver.save(self.sess, path)

    def load(self, path):
        """
        Load the model from the specified path.
        """
        self.saver.restore(self.sess, path)

    def train_on_batch(self, X, R, Y, keep_prob=1.0):
        """
        Train model for one step on specified batch
        """
        c, _ = self.sess.run([self.cost, self.optimizer],
                   {self.X: X, self.R: R, self.Y: Y, self.keep_prob: keep_prob}
                            )
        return c

    def get_cost(self, X, R, Y):
        """
        Get the cost on a specified batch
        """
        c = self.sess.run(self.cost, {self.X: X, self.R: R, self.Y: Y,
                          self.keep_prob: 1.0})
        return c

    def get_output(self, X, R):
        """
        Get the predictions given input data
        """
        _, out = self.sess.run(self.network, {self.X: X, self.R: R,
                               self.keep_prob: 1.0})

        return out

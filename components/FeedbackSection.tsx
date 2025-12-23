import React, { useState, useEffect } from 'react';
import { supabase, Review } from '../services/supabaseClient';
import { Star, Send, User, MessageSquare, Loader2, AlertCircle } from 'lucide-react';

export const FeedbackSection: React.FC = () => {
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  
  // Form State
  const [name, setName] = useState('');
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    fetchReviews();
  }, []);

  const fetchReviews = async () => {
    try {
      // Assuming a table named 'reviews' exists
      const { data, error } = await supabase
        .from('reviews')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) {
        throw error;
      }
      
      if (data) {
        setReviews(data);
        setConnectionError(false);
      }
    } catch (err: any) {
      console.warn("Supabase Error:", err.message);
      // If table doesn't exist (404) or connection fails
      setConnectionError(true);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !comment.trim()) {
      setError('Please fill in all fields.');
      return;
    }
    setError('');
    setSubmitting(true);

    try {
      const { error } = await supabase
        .from('reviews')
        .insert([{ name, rating, comment }]);

      if (error) throw error;

      // Reset form and refetch
      setName('');
      setComment('');
      setRating(5);
      await fetchReviews();
    } catch (err: any) {
      setError('Failed to submit review. ' + (err.message || 'Check network'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mt-12 pt-8 border-t border-gray-200 dark:border-gray-800">
      <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-6 flex items-center gap-2">
        <MessageSquare className="w-6 h-6 text-sec-red" />
        Community Feedback
      </h3>

      <div className="grid md:grid-cols-2 gap-8">
        {/* Form */}
        <div className="bg-white dark:bg-card-bg p-6 rounded-xl border border-gray-300 dark:border-gray-700 shadow-sm">
          <h4 className="text-lg font-semibold mb-4 dark:text-gray-200">Leave a Review</h4>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">Name</label>
              <input 
                type="text" 
                value={name}
                onChange={e => setName(e.target.value)}
                className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none"
                placeholder="Cyber_Punk_2077"
              />
            </div>
            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">Rating</label>
              <div className="flex gap-2">
                {[1, 2, 3, 4, 5].map((star) => (
                  <button
                    key={star}
                    type="button"
                    onClick={() => setRating(star)}
                    className="focus:outline-none transition-transform hover:scale-110"
                  >
                    <Star className={`w-6 h-6 ${star <= rating ? 'fill-yellow-500 text-yellow-500' : 'text-gray-300 dark:text-gray-600'}`} />
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs font-bold uppercase text-gray-500 mb-1">Comment</label>
              <textarea 
                value={comment}
                onChange={e => setComment(e.target.value)}
                rows={3}
                className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded p-2 text-sm dark:text-white focus:ring-2 focus:ring-sec-red focus:outline-none resize-none"
                placeholder="Great insights on Shift Left..."
              />
            </div>
            
            {error && <p className="text-xs text-red-500">{error}</p>}

            <button 
              type="submit" 
              disabled={submitting}
              className="w-full bg-sec-red hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition disabled:opacity-50"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Submit Review
            </button>
          </form>
        </div>

        {/* List */}
        <div className="space-y-4 max-h-[500px] overflow-y-auto">
          {loading ? (
             <div className="flex justify-center p-8"><Loader2 className="w-8 h-8 animate-spin text-gray-400" /></div>
          ) : connectionError ? (
             <div className="flex flex-col items-center justify-center p-8 text-center bg-red-50 dark:bg-red-900/10 rounded-lg border border-red-100 dark:border-red-900/30">
                <AlertCircle className="w-8 h-8 text-red-500 mb-2" />
                <p className="text-sm text-red-600 dark:text-red-400">Unable to load reviews.</p>
                <p className="text-xs text-gray-500 mt-1">Check if 'reviews' table exists in Supabase.</p>
             </div>
          ) : reviews.length === 0 ? (
             <div className="text-center p-8 text-gray-500 italic">No reviews yet. Be the first!</div>
          ) : (
            reviews.map((rev, idx) => (
              <div key={rev.id || idx} className="bg-gray-50 dark:bg-gray-800/50 p-4 rounded-lg border border-gray-200 dark:border-gray-700/50 animate-fade-in">
                 <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-2">
                        <div className="bg-gray-200 dark:bg-gray-700 p-1.5 rounded-full">
                            <User className="w-4 h-4 text-gray-600 dark:text-gray-300" />
                        </div>
                        <span className="font-bold text-sm text-gray-800 dark:text-gray-200">{rev.name}</span>
                    </div>
                    <div className="flex">
                        {[...Array(5)].map((_, i) => (
                            <Star key={i} className={`w-3 h-3 ${i < rev.rating ? 'fill-yellow-500 text-yellow-500' : 'text-gray-300 dark:text-gray-600'}`} />
                        ))}
                    </div>
                 </div>
                 <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">"{rev.comment}"</p>
                 <span className="text-[10px] text-gray-400 mt-2 block">
                    {rev.created_at ? new Date(rev.created_at).toLocaleDateString() : 'Just now'}
                 </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

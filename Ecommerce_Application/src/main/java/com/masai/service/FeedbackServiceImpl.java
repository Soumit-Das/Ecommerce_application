package com.masai.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.masai.exception.CustomersException;
import com.masai.exception.FeedbackException;
import com.masai.model.Customers;
import com.masai.model.Feedback;
import com.masai.repository.FeedbackRepository;

@Service
public class FeedbackServiceImpl implements FeedbackService {

	@Autowired
	private FeedbackRepository feedbackRepository;

	@Override
	public Feedback addFeedback(Feedback feedback) throws FeedbackException {

		if (feedbackRepository.existsById(feedback.getFeedbackId())) {
			throw new FeedbackException("Feedback already exists with id " + feedback.getFeedbackId());
		}

		return feedbackRepository.save(feedback);

	}

	@Override
	public Feedback getFeedbackById(int fid) throws FeedbackException {

		Optional<Feedback> feedback = feedbackRepository.findById(fid);

		if (feedback.isEmpty()) {
			throw new FeedbackException("feedback doesn't exists with id " + fid);
		}

		return feedback.get();
	}

	@Override
	public List<Feedback> getAllFeedback() throws FeedbackException {

		List<Feedback> list = feedbackRepository.findAll();

		if (list.isEmpty()) {
			throw new FeedbackException("No feedback found");
		}

		return list;
	}

	@Override
	public Feedback updateFeedback(int fid, Feedback feedback) throws FeedbackException {

		Optional<Feedback> feedbacks = feedbackRepository.findById(fid);

		if (feedbacks.isEmpty()) {
			throw new FeedbackException("Feedback doesn't exists with id " + fid);
		}

		Feedback custo = feedbacks.get();

		custo.setCustomerFeedback(feedback.getCustomerFeedback());
		custo.setCancelationFeedback(feedback.isCancelationFeedback());
		custo.setDeliveredFeedback(feedback.isDeliveredFeedback());
		custo.setReturnFeedback(feedback.isReturnFeedback());
		custo.setRating(feedback.getRating());
		custo.setFeedbackCreatedDate(feedback.getFeedbackCreatedDate());

		return feedbackRepository.save(custo);
	}

	@Override
	public Feedback deleteFeedback(int fid) throws FeedbackException {

		Optional<Feedback> feedbacks = feedbackRepository.findById(fid);

		if (feedbacks.isEmpty()) {
			throw new FeedbackException("No feedback exists with id " + fid);
		}

		feedbackRepository.delete(feedbacks.get());

		return feedbacks.get();
	}

}
